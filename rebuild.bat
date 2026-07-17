@echo off
cd /d G:\ETestingCenter
python -m PyInstaller ETTestingCenterCN.spec --noconfirm > G:\ETestingCenter\build_log.txt 2>&1
echo BUILD_EXIT_CODE=%ERRORLEVEL% >> G:\ETestingCenter\build_log.txt
