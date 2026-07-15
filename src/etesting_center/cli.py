from __future__ import annotations

import argparse
from pathlib import Path

from etesting_center.engine.scanner import Scanner
from etesting_center.reports.writers import write_report


def default_data_dir() -> Path:
    return Path(__file__).resolve().parent / "data"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ETestingCenter", description="Local read-only threat discovery tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a file or directory")
    scan.add_argument("--path", required=True, help="file or directory to scan")
    scan.add_argument("--format", choices=("json", "html", "txt"), default="html", help="report format")
    scan.add_argument("--out", required=True, help="report output path")
    scan.add_argument("--data-dir", default=str(default_data_dir()), help="local database and rules directory")
    scan.add_argument("--workers", type=int, default=4, help="parallel scan workers")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        target = Path(args.path).expanduser().resolve()
        output = Path(args.out).expanduser().resolve()
        scanner = Scanner(Path(args.data_dir).expanduser().resolve(), max_workers=args.workers)

        def show_progress(done: int, total: int, path: str) -> None:
            print(f"[{done}/{total}] {path}")

        report = scanner.scan(target, progress=show_progress)
        write_report(report, output, args.format)
        print(f"Report written: {output}")
        print(
            "Summary: "
            f"scanned={report.summary.scanned}, safe={report.summary.safe}, "
            f"suspicious={report.summary.suspicious}, malicious={report.summary.malicious}, errors={report.summary.errors}"
        )
        return 1 if report.summary.malicious or report.summary.suspicious or report.summary.errors else 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
