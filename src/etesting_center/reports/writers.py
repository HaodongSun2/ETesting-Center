from __future__ import annotations

import json
from dataclasses import asdict
from html import escape
from pathlib import Path

from etesting_center import APP_NAME, APP_VERSION
from etesting_center.engine.models import ScanReport


def report_to_dict(report: ScanReport) -> dict:
    return asdict(report)


def write_report(report: ScanReport, output: Path, fmt: str) -> Path:
    fmt = fmt.lower()
    output.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        output.write_text(json.dumps(report_to_dict(report), indent=2, ensure_ascii=False), encoding="utf-8")
    elif fmt == "html":
        output.write_text(render_html(report), encoding="utf-8")
    elif fmt == "txt":
        output.write_text(render_text(report), encoding="utf-8")
    else:
        raise ValueError(f"Unsupported report format: {fmt}")
    return output


def render_text(report: ScanReport) -> str:
    lines = [
        f"{APP_NAME} {APP_VERSION} scan report",
        f"Target: {report.target}",
        f"Started: {report.started_at}",
        f"Finished: {report.finished_at}",
        f"YARA enabled: {report.yara_enabled}",
        "",
        "Summary",
        f"  Scanned: {report.summary.scanned}",
        f"  Safe: {report.summary.safe}",
        f"  Suspicious: {report.summary.suspicious}",
        f"  Malicious: {report.summary.malicious}",
        f"  Errors: {report.summary.errors}",
        "",
        "Results",
    ]
    for result in report.results:
        lines.extend(
            [
                f"[{result.risk.upper()}] {result.path}",
                f"  Score: {result.score}",
                f"  Type: {result.file_type}",
                f"  Size: {result.size}",
                f"  SHA-256: {result.sha256}",
            ]
        )
        if result.error:
            lines.append(f"  Error: {result.error}")
        for finding in result.findings:
            lines.append(f"  - {finding.engine}:{finding.rule} ({finding.confidence}) {finding.description}")
        lines.append("")
    return "\n".join(lines)


def render_html(report: ScanReport) -> str:
    rows = []
    for result in report.results:
        findings = "<br>".join(
            escape(f"{item.engine}:{item.rule} ({item.confidence}) {item.description}") for item in result.findings
        ) or "-"
        rows.append(
            "<tr>"
            f"<td><span class='badge {escape(result.risk)}'>{escape(result.risk)}</span></td>"
            f"<td>{escape(result.path)}</td>"
            f"<td>{result.score}</td>"
            f"<td>{escape(result.file_type)}</td>"
            f"<td>{result.size}</td>"
            f"<td class='hash'>{escape(result.sha256)}</td>"
            f"<td>{findings}</td>"
            "</tr>"
        )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{escape(APP_NAME)} Report</title>
<style>
body {{ margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f5f6f8; color: #1d1d1f; }}
main {{ max-width: 1180px; margin: 0 auto; padding: 36px 24px; }}
h1 {{ margin: 0; font-size: 30px; font-weight: 680; letter-spacing: 0; }}
.meta {{ color: #62666d; margin-top: 8px; line-height: 1.5; }}
.summary {{ display: grid; grid-template-columns: repeat(5, minmax(120px, 1fr)); gap: 12px; margin: 26px 0; }}
.metric {{ background: rgba(255,255,255,.82); border: 1px solid #e3e5e8; border-radius: 8px; padding: 14px; }}
.metric strong {{ display: block; font-size: 24px; }}
.metric span {{ color: #62666d; font-size: 13px; }}
table {{ width: 100%; border-collapse: collapse; background: rgba(255,255,255,.88); border: 1px solid #e2e4e8; border-radius: 8px; overflow: hidden; }}
th, td {{ padding: 10px 12px; border-bottom: 1px solid #edf0f2; text-align: left; vertical-align: top; font-size: 13px; }}
th {{ color: #62666d; font-weight: 600; background: #fbfbfc; }}
.hash {{ font-family: "Cascadia Mono", Consolas, monospace; word-break: break-all; }}
.badge {{ display: inline-block; min-width: 72px; text-align: center; border-radius: 999px; padding: 4px 8px; font-weight: 650; }}
.safe {{ background: #e7f5ee; color: #12663d; }}
.suspicious {{ background: #fff1cf; color: #805400; }}
.malicious {{ background: #ffe0df; color: #9b1c16; }}
</style>
</head>
<body>
<main>
<h1>{escape(APP_NAME)} scan report</h1>
<div class="meta">Target: {escape(report.target)}<br>Started: {escape(report.started_at)}<br>Finished: {escape(report.finished_at)}<br>YARA enabled: {report.yara_enabled}</div>
<section class="summary">
<div class="metric"><strong>{report.summary.scanned}</strong><span>Scanned</span></div>
<div class="metric"><strong>{report.summary.safe}</strong><span>Safe</span></div>
<div class="metric"><strong>{report.summary.suspicious}</strong><span>Suspicious</span></div>
<div class="metric"><strong>{report.summary.malicious}</strong><span>Malicious</span></div>
<div class="metric"><strong>{report.summary.errors}</strong><span>Errors</span></div>
</section>
<table>
<thead><tr><th>Risk</th><th>Path</th><th>Score</th><th>Type</th><th>Size</th><th>SHA-256</th><th>Findings</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
</main>
</body>
</html>
"""
