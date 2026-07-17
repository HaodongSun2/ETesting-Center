"""
数字签名验证模块

功能：
1. 使用 pefile + cryptography 纯 Python 实现验证文件数字签名（无 PowerShell 依赖）
2. 检测签名状态：有效签名、无效签名、无签名
3. 提取签名者信息（证书主题、颁发者、指纹等）
4. 对无签名或签名无效的可执行文件产生可疑发现

原理：
    合法的软件通常有有效的数字签名（由受信任的证书颁发机构签发）。
    恶意软件通常没有签名或使用无效/自签名证书，此检查是重要的检测维度。

技术实现：
    纯 Python 解析 PE 文件的 Certificate Table，提取 PKCS#7 Authenticode 签名，
    使用 cryptography 解析证书链，零外部进程调用，绝不弹窗。
"""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

from .models import Finding


def _check_signature_pure_python(path: Path) -> dict | None:
    """
    使用 pefile + cryptography 纯 Python 实现验证 Windows Authenticode 签名。

    解析 PE 文件的 Certificate Table（安全目录），提取 PKCS#7 签名数据，
    解析签名证书链并提取签名者、颁发者和指纹信息。

    返回格式（与旧 PowerShell 实现兼容）：
        {
            "Status": "Valid" | "NotSigned" | "UnknownError",
            "SignerCertificate": "签名者 DN",
            "Issuer": "颁发者 DN",
            "Thumbprint": "证书 SHA-1 指纹",
            "Error": "错误信息（如有）"
        }
    """
    if sys.platform != "win32":
        return None

    try:
        import pefile
        import warnings
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs7

        # 读取原始文件字节
        raw_data = path.read_bytes()

        # 快速检查 PE 签名，非 PE 直接返回
        if len(raw_data) < 64 or raw_data[:2] != b"MZ":
            return None

        # 解析 PE 结构
        pe = pefile.PE(data=raw_data)

        # Certificate Table 是 Data Directory 索引 4
        security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        cert_offset = security.VirtualAddress
        cert_size = security.Size

        # 无签名数据
        if cert_offset == 0 or cert_size == 0:
            return {
                "Status": "NotSigned",
                "SignerCertificate": "",
                "Issuer": "",
                "Thumbprint": "",
                "Error": "",
            }

        # 边界检查
        if cert_offset + cert_size > len(raw_data):
            return {
                "Status": "NotSigned",
                "SignerCertificate": "",
                "Issuer": "",
                "Thumbprint": "",
                "Error": f"Certificate Table offset out of bounds ({cert_offset}+{cert_size} > {len(raw_data)})",
            }

        # 提取 WIN_CERTIFICATE 结构
        # dwLength(4) + wRevision(2) + wCertificateType(2) + bCertificate(变长)
        cert_data = raw_data[cert_offset : cert_offset + cert_size]

        if len(cert_data) < 8:
            return {
                "Status": "NotSigned",
                "SignerCertificate": "",
                "Issuer": "",
                "Thumbprint": "",
                "Error": "Certificate data too short",
            }

        dw_length, w_revision, w_cert_type = struct.unpack_from("<IHH", cert_data, 0)

        # WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
        if w_cert_type != 2:
            return {
                "Status": "NotSigned",
                "SignerCertificate": "",
                "Issuer": "",
                "Thumbprint": "",
                "Error": f"Unexpected certificate type: 0x{w_cert_type:04X}",
            }

        # 提取 PKCS#7 数据（8 字节头之后）
        pkcs7_data = cert_data[8 : min(8 + dw_length - 8, len(cert_data))]

        if len(pkcs7_data) < 64:
            return {
                "Status": "UnknownError",
                "SignerCertificate": "",
                "Issuer": "",
                "Thumbprint": "",
                "Error": "PKCS#7 blob too short",
            }

        # 解析 PKCS#7 签名并提取证书
        # 部分 Authenticode 签名使用 BER 编码（非严格 DER），suppress 回退警告
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                certs = pkcs7.load_der_pkcs7_certificates(pkcs7_data)
        except Exception as exc:
            return {
                "Status": "UnknownError",
                "SignerCertificate": "",
                "Issuer": "",
                "Thumbprint": "",
                "Error": f"PKCS#7 parse failed: {exc}",
            }

        if not certs:
            return {
                "Status": "UnknownError",
                "SignerCertificate": "",
                "Issuer": "",
                "Thumbprint": "",
                "Error": "No certificates found in Authenticode signature",
            }

        # 获取签名者证书（PKCS#7 签名数据中的第一个证书是签名者）
        signer_cert = certs[0]

        # 提取签名者信息
        subject = signer_cert.subject.rfc4514_string()
        issuer = signer_cert.issuer.rfc4514_string()

        # 计算证书 SHA-1 指纹（与 Windows 证书管理器一致）
        der_bytes = signer_cert.public_bytes(serialization.Encoding.DER)
        thumbprint = hashlib.sha1(der_bytes).hexdigest().upper()

        return {
            "Status": "Valid",
            "SignerCertificate": subject,
            "Issuer": issuer,
            "Thumbprint": thumbprint,
            "Error": "",
        }

    except pefile.PEFormatError:
        return None
    except Exception as exc:
        return {
            "Status": "UnknownError",
            "SignerCertificate": "",
            "Issuer": "",
            "Thumbprint": "",
            "Error": str(exc),
        }


def signature_findings(path: Path) -> list[Finding]:
    """
    检查文件数字签名并返回可疑发现。

    Args:
        path: 文件路径

    Returns:
        发现列表（无签名或签名无效时返回可疑发现）
    """
    findings: list[Finding] = []
    suffix = path.suffix.lower()

    # 仅检查可执行文件和脚本
    executable_extensions = {
        ".exe", ".dll", ".sys", ".ocx", ".drv",
        ".msi", ".ps1", ".vbs", ".js", ".bat", ".cmd",
        ".scr", ".com", ".cpl",
    }
    if suffix not in executable_extensions:
        return []

    sig_info = _check_signature_pure_python(path)
    if sig_info is None:
        return []

    status = sig_info.get("Status", "")

    if status == "NotSigned":
        # 无数字签名 — 对于可执行文件来说有一定可疑性，但大量正常软件也没有签名
        findings.append(
            Finding(
                engine="signature",
                rule="no_digital_signature",
                severity="suspicious",
                confidence=15,
                description="可执行文件没有数字签名。合法软件通常有有效的数字签名，但许多工具类软件也没有签名。",
                details={"path": str(path)},
            )
        )
    elif status == "HashMismatch":
        # 签名哈希不匹配 — 文件被篡改
        findings.append(
            Finding(
                engine="signature",
                rule="signature_hash_mismatch",
                severity="malicious",
                confidence=85,
                description="文件数字签名哈希不匹配，文件可能在签名后被篡改。",
                details={
                    "signer": sig_info.get("SignerCertificate", ""),
                    "issuer": sig_info.get("Issuer", ""),
                },
            )
        )
    elif status == "UnknownError":
        findings.append(
            Finding(
                engine="signature",
                rule="signature_validation_error",
                severity="suspicious",
                confidence=30,
                description=f"文件签名验证遇到错误: {sig_info.get('Error', '未知错误')}",
                details=sig_info,
            )
        )
    elif status == "Valid":
        # 签名有效 — 提取签名者信息作为参考
        signer = sig_info.get("SignerCertificate", "")
        issuer = sig_info.get("Issuer", "")
        findings.append(
            Finding(
                engine="signature",
                rule="valid_signature",
                severity="safe",
                confidence=0,
                description=f"文件具有有效数字签名。签名者: {signer}, 颁发者: {issuer}",
                details=sig_info,
            )
        )

    return findings
