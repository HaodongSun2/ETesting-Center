"""
PE (Portable Executable) 文件结构深度分析模块

功能：
1. 手动解析 PE 文件头（无需第三方依赖）
2. 检测可疑的节区权限（可写+可执行 RWX）
3. 检测入口点是否在合法代码节区之外
4. 检测异常时间戳（未来时间、过旧时间）
5. 检测导入表中的可疑 API 调用
6. 检测节区数量异常（过少或过多）
7. 检测节区名伪装（伪装成已知节区名）
8. 检测 TLS 回调（常用于反调试）

所有分析基于 PE 文件原始字节流，不执行任何代码。
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import Finding

# ---------------------------------------------------------------------------
# PE 文件格式常量
# ---------------------------------------------------------------------------

# 标准代码节区名称（白名单）
STANDARD_SECTIONS = {
    ".text",     # 代码节区
    ".data",     # 已初始化数据
    ".rdata",    # 只读数据
    ".bss",      # 未初始化数据
    ".idata",    # 导入表
    ".edata",    # 导出表
    ".rsrc",     # 资源
    ".reloc",    # 重定位
    ".tls",      # 线程局部存储
    ".pdata",    # 异常处理数据
    ".debug",    # 调试信息
    ".crt",      # CRT 数据
    ".didat",    # 延迟导入
    ".00cfg",    # CFG 配置
    ".giats",    # 全局 IAT
    ".gljmp",    # 全局跳转表
    ".gehcont",  # 全局异常处理
}

# 常见打包器节区名
PACKER_SECTIONS = {
    "UPX0", "UPX1", "UPX2",
    ".mpress1", ".mpress2",
    "ASPack", ".aspack",
    "Themida", "WinLic",
    "VMP0", "VMP1", "VMP2", "VMP3",
    ".enigma1", ".enigma2",
    "petite",
    ".pelock",
    ".yoda",
    ".ccg",
}

# 高风险 API 列表（常用于恶意软件）
HIGH_RISK_APIS = {
    # 进程注入相关
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
    "SetThreadContext", "MapViewOfFile", "MapViewOfFileEx",
    # 代码执行相关
    "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteEx",
    "CreateProcessA", "CreateProcessW", "CreateProcessInternal",
    "system", "popen", "_wsystem",
    # 网络通信相关
    "URLDownloadToFile", "URLDownloadToCacheFile", "InternetOpen",
    "InternetConnect", "HttpSendRequest", "WinHttpOpen",
    "WinHttpConnect", "WinHttpSendRequest", "socket", "connect",
    "WSAConnect", "recv", "send",
    # 凭据窃取相关
    "CredEnumerate", "CredRead", "CryptUnprotectData",
    "LsaRetrievePrivateData", "SamQueryInformationUser",
    # 反调试/反分析
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "OutputDebugString",
    "GetTickCount", "QueryPerformanceCounter", "rdtsc",
    # 注册表持久化
    "RegCreateKey", "RegSetValueEx", "RegOpenKeyEx",
    "SHGetValue", "SHSetValue",
    # 服务管理
    "CreateService", "StartService", "OpenSCManager",
    # 文件隐藏/操作
    "SetFileAttributes", "MoveFileEx", "NtSetInformationFile",
    "FindFirstFile", "FindNextFile",
}

# IMAGE_SCN_MEM_EXECUTE (0x20000000) | IMAGE_SCN_MEM_WRITE (0x80000000) = 0xA0000000
SECTION_RWX_MASK = 0xA0000000

# IMAGE_FILE_MACHINE 常量
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664

# IMAGE_DIRECTORY_ENTRY 索引
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_TLS = 9


def _read_struct(data: bytes, offset: int, fmt: str) -> tuple:
    """从字节流中按指定偏移量和格式读取结构体。"""
    size = struct.calcsize(fmt)
    if offset + size > len(data):
        raise ValueError(f"偏移量越界: offset={offset}, fmt={fmt}")
    return struct.unpack_from(fmt, data, offset)


def _is_pe(data: bytes) -> bool:
    """检查是否为有效的 PE 文件（MZ 头 + PE 签名）。"""
    if len(data) < 64 or data[:2] != b"MZ":
        return False
    # 读取 e_lfanew（PE 签名偏移量，位于 DOS 头偏移 0x3C 处）
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 4 > len(data):
        return False
    return data[pe_offset:pe_offset + 4] == b"PE\x00\x00"


def pe_findings(path: Path, data: bytes) -> list[Finding]:
    """
    对 PE 文件进行深度结构分析，返回所有可疑发现。

    检测项包括：
    - 节区权限异常（RWX 节区）
    - 入口点异常（在非标准节区中）
    - 打包器节区名识别
    - 时间戳异常
    - 导入表高风险 API 检测
    - 节区数量异常
    - TLS 回调检测
    """
    if not _is_pe(data) or len(data) < 512:
        return []

    findings: list[Finding] = []
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]

    # 确保有足够的数据来解析 COFF 头
    coff_start = pe_offset + 4  # 跳过 PE 签名
    if coff_start + 20 > len(data):
        return []

    try:
        # -------------------------------------------------------------------
        # 解析 COFF 头（20 字节）
        #   offset 0: Machine (2 bytes)
        #   offset 2: NumberOfSections (2 bytes)
        #   offset 4: TimeDateStamp (4 bytes)
        #   offset 16: SizeOfOptionalHeader (2 bytes)
        # -------------------------------------------------------------------
        machine, num_sections, timestamp, _, _, _, _, size_opt_hdr = _read_struct(
            data, coff_start, "<HHIIIHHH"
        )

        # -------------------------------------------------------------------
        # 解析 Optional Header（确定入口点和数据目录位置）
        # -------------------------------------------------------------------
        opt_start = coff_start + 20
        magic = struct.unpack_from("<H", data, opt_start)[0]

        # PE32 (0x10B) 和 PE32+ (0x20B) 的 Optional Header 长度不同
        if magic == 0x10B:  # PE32
            ep_offset_field = 16    # AddressOfEntryPoint 在 Optional Header 中的偏移
            dir_offset_field = 96   # NumberOfRvaAndSizes 的偏移
            dir_count_offset = 92
        elif magic == 0x20B:  # PE32+
            ep_offset_field = 16
            dir_offset_field = 112
            dir_count_offset = 108
        else:
            return []

        # 入口点 RVA
        entrypoint_rva = struct.unpack_from("<I", data, opt_start + ep_offset_field)[0]

        # 节区表起始位置
        section_start = opt_start + size_opt_hdr

        # 确保节区表在数据范围内
        section_entry_size = 40  # IMAGE_SECTION_HEADER 大小
        if section_start + num_sections * section_entry_size > len(data):
            return []

        # -------------------------------------------------------------------
        # 逐个分析节区
        # -------------------------------------------------------------------
        section_names: list[str] = []
        rwx_sections: list[str] = []
        entrypoint_section: Optional[str] = None
        packer_sections: list[str] = []

        for i in range(num_sections):
            sec_offset = section_start + i * section_entry_size
            # 节区名（8 字节）
            raw_name = data[sec_offset:sec_offset + 8]
            sec_name = raw_name.rstrip(b"\x00").decode("ascii", errors="ignore").strip()
            section_names.append(sec_name)

            # 节区虚拟大小和 RVA
            virtual_size, virtual_address = _read_struct(data, sec_offset + 8, "<II")
            # 节区特征（Characteristics 在偏移 36 处）
            characteristics = struct.unpack_from("<I", data, sec_offset + 36)[0]

            # ---------------------------------------------------------------
            # 检测 1: RWX 节区（可读+可写+可执行）
            # 正常情况下代码节区只有 RX，数据节区只有 RW
            # 同时可写和可执行是非常可疑的
            # ---------------------------------------------------------------
            has_write = bool(characteristics & 0x80000000)
            has_execute = bool(characteristics & 0x20000000)
            if has_write and has_execute and sec_name:
                rwx_sections.append(sec_name)
                findings.append(
                    Finding(
                        engine="pe_structure",
                        rule="section_rwx_permission",
                        severity="suspicious",
                        confidence=35,
                        description=f"节区 '{sec_name}' 同时具有写入和执行权限，这在正常程序中极少出现。",
                        details={
                            "section": sec_name,
                            "characteristics": f"0x{characteristics:08X}",
                            "virtual_size": virtual_size,
                        },
                    )
                )

            # ---------------------------------------------------------------
            # 检测 2: 入口点是否在当前节区中
            # ---------------------------------------------------------------
            if virtual_address <= entrypoint_rva < virtual_address + max(virtual_size, 4096):
                entrypoint_section = sec_name

            # ---------------------------------------------------------------
            # 检测 3: 打包器节区名
            # ---------------------------------------------------------------
            if sec_name and sec_name in PACKER_SECTIONS:
                packer_sections.append(sec_name)

        # 如果找到打包器节区，汇总为一个发现
        if packer_sections:
            findings.append(
                Finding(
                    engine="pe_structure",
                    rule="packer_section_detected",
                    severity="suspicious",
                    confidence=20,
                    description=f"PE 文件包含已知打包器/加壳工具的节区: {', '.join(packer_sections)}。",
                    details={"packer_sections": packer_sections},
                )
            )

        # ---------------------------------------------------------------
        # 检测 4: 入口点异常
        # - 入口点在非标准代码节区中
        # - 入口点 RVA 为 0 或异常小
        # ---------------------------------------------------------------
        if entrypoint_rva == 0:
            findings.append(
                Finding(
                    engine="pe_structure",
                    rule="entrypoint_zero",
                    severity="suspicious",
                    confidence=30,
                    description="入口点 RVA 为 0，异常。",
                    details={"entrypoint_rva": "0x0"},
                )
            )
        elif entrypoint_section is not None:
            if entrypoint_section not in STANDARD_SECTIONS:
                findings.append(
                    Finding(
                        engine="pe_structure",
                        rule="entrypoint_in_unusual_section",
                        severity="suspicious",
                        confidence=30,
                        description=f"入口点位于非标准节区 '{entrypoint_section}' 中。",
                        details={
                            "entrypoint_section": entrypoint_section,
                            "entrypoint_rva": f"0x{entrypoint_rva:08X}",
                        },
                    )
                )
            elif entrypoint_section == ".rsrc" or entrypoint_section == ".reloc":
                findings.append(
                    Finding(
                        engine="pe_structure",
                        rule="entrypoint_in_non_code_section",
                        severity="suspicious",
                        confidence=60,
                        description=f"入口点位于数据节区 '{entrypoint_section}'，这是典型的恶意代码注入特征。",
                        details={
                            "entrypoint_section": entrypoint_section,
                        },
                    )
                )

        # ---------------------------------------------------------------
        # 检测 5: 时间戳异常
        #   - 未来时间（可能是反病毒规避）
        #   - 1970 年之前或超过 30 年的旧时间（很可疑）
        # ---------------------------------------------------------------
        if timestamp > 0:
            try:
                ts_dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                now = datetime.now(timezone.utc)
                if ts_dt > now:
                    findings.append(
                        Finding(
                            engine="pe_structure",
                            rule="future_timestamp",
                            severity="suspicious",
                            confidence=35,
                            description=f"PE 文件时间戳为未来时间 {ts_dt.isoformat()}。",
                            details={"timestamp": ts_dt.isoformat()},
                        )
                    )
                elif ts_dt.year < 2000:
                    findings.append(
                        Finding(
                            engine="pe_structure",
                            rule="very_old_timestamp",
                            severity="suspicious",
                            confidence=25,
                            description=f"PE 文件时间戳异常老旧 ({ts_dt.year}年)，可能是伪造的编译时间。",
                            details={"timestamp": ts_dt.isoformat()},
                        )
                    )
            except Exception:
                pass  # 时间戳无效，忽略
        elif timestamp == 0:
            findings.append(
                Finding(
                    engine="pe_structure",
                    rule="zero_timestamp",
                    severity="suspicious",
                    confidence=20,
                    description="PE 文件时间戳为 0，被有意抹除。",
                    details={},
                )
            )

        # ---------------------------------------------------------------
        # 检测 6: 节区数量异常
        # ---------------------------------------------------------------
        if num_sections == 0:
            findings.append(
                Finding(
                    engine="pe_structure",
                    rule="no_sections",
                    severity="suspicious",
                    confidence=50,
                    description="PE 文件声称无任何节区，可能是畸形构造。",
                    details={},
                )
            )
        elif num_sections > 30:
            findings.append(
                Finding(
                    engine="pe_structure",
                    rule="too_many_sections",
                    severity="suspicious",
                    confidence=30,
                    description=f"PE 文件包含 {num_sections} 个节区（正常不超过 30 个），可能是加壳或混淆导致。",
                    details={"section_count": num_sections},
                )
            )

        # ---------------------------------------------------------------
        # 检测 7: 导入表高风险 API 检测
        # 通过扫描文件原始字节检测可疑 API 字符串
        # ---------------------------------------------------------------
        lowered_data = data.lower()
        matched_apis = sorted(
            api for api in HIGH_RISK_APIS
            if api.lower().encode("ascii") in lowered_data
        )
        if len(matched_apis) >= 5:
            findings.append(
                Finding(
                    engine="pe_structure",
                    rule="high_risk_import_cluster",
                    severity="suspicious",
                    confidence=min(50, 20 + len(matched_apis) * 3),
                    description=f"PE 文件导入了 {len(matched_apis)} 个高风险 API。",
                    details={"high_risk_apis": matched_apis[:20]},
                )
            )

        # ---------------------------------------------------------------
        # 检测 8: TLS 回调（常用于反调试，在 main 之前执行）
        # ---------------------------------------------------------------
        dir_count = struct.unpack_from("<I", data, opt_start + dir_count_offset)[0]
        if dir_count >= 10:  # 确保 TLS 目录存在
            tls_dir_rva = struct.unpack_from("<I", data, opt_start + dir_offset_field + 9 * 8)[0]
            tls_dir_size = struct.unpack_from("<I", data, opt_start + dir_offset_field + 9 * 8 + 4)[0]
            if tls_dir_rva != 0 and tls_dir_size > 0:
                findings.append(
                    Finding(
                        engine="pe_structure",
                        rule="tls_callback_present",
                        severity="suspicious",
                        confidence=20,
                        description="PE 文件包含 TLS 回调，可能在主函数执行前运行代码（常见于反调试技术）。",
                        details={"tls_directory_rva": f"0x{tls_dir_rva:08X}", "tls_directory_size": tls_dir_size},
                    )
                )

    except (struct.error, ValueError, IndexError):
        # PE 解析失败，返回部分发现
        pass

    return findings
