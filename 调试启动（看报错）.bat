@echo off
chcp 936 >nul
cd /d "%~dp0"
set PY=C:\Users\Administrator\AppData\Local\Programs\Python\Python310\python.exe
if not exist "%PY%" set PY=python
"%PY%" "%~dp0boot_doctor.py"
echo.
echo ---- 程序已退出，按任意键关闭 ----
pause >nul
