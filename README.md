# ETesting Center

ETesting Center is a local, read-only threat discovery tool for Windows. It scans files, records evidence, and exports reports. It does not quarantine, delete, repair, upload, or modify scanned files.

## Features

- Local hash matching with `src/etesting_center/data/hashes.json`
- Optional YARA rules from `src/etesting_center/data/rules`
- Static heuristic checks for PE files, scripts, and macro-capable documents
- GUI scanning for single files, custom folders, and quick scan targets
- CLI scanning for automation
- JSON, HTML, and TXT report export

## CLI

```cmd
python -m etesting_center.cli scan --path "C:\path\to\scan" --format html --out report.html
```

When running from source, set `PYTHONPATH=src` first or install the project in editable mode.

## Build

```powershell
.\build.ps1
```

The executable is generated at:

```text
dist\ETestingCenter\ETestingCenter.exe
```

## Local Data

Add known hashes to `src/etesting_center/data/hashes.json` as a list:

```json
[
  {
    "sha256": "example_sha256_here",
    "name": "Example.Threat",
    "family": "ExampleFamily",
    "source": "local"
  }
]
```

Add YARA files with `.yar` or `.yara` extensions under `src/etesting_center/data/rules`.

## Safety Boundary

This tool is intentionally detection-only. It never executes scanned files and provides no automatic remediation controls.
