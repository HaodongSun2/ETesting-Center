@echo off
python -m PyInstaller G:\ETestingCenter\ETTestingCenterCN.spec --noconfirm --distpath G:\ETestingCenter\dist --workpath G:\ETestingCenter\build > G:\ETestingCenter\build_log.txt 2>&1
echo BUILD_EXIT_CODE=%ERRORLEVEL% >> G:\ETestingCenter\build_log.txt
