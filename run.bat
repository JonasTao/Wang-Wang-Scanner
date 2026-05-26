@echo off
cd /d "%~dp0"
REM 清除已弃用的 Qt DPI 变量，避免启动警告
set QT_DEVICE_PIXEL_RATIO=
set QT_DEVICE_PIXEL_RATIO_2=
if not defined QT_AUTO_SCREEN_SCALE_FACTOR set QT_AUTO_SCREEN_SCALE_FACTOR=1
python main.py
pause
