@echo off
chcp 936 >nul
cd /d "%~dp0"
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo 正在请求管理员权限...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
set PY=C:\Users\Administrator\AppData\Local\Programs\Python\Python310\pythonw.exe
if not exist "%PY%" set PY=C:\Users\Administrator\AppData\Local\Programs\Python\Python310\python.exe
if not exist "%PY%" set PY=pythonw
start "" "%PY%" "%~dp0boot_doctor.py"
exit /b
