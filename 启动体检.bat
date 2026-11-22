@echo off
chcp 936 >nul
cd /d "%~dp0"
rem 提权交给程序自己（ShellExecute runas），这里不再先起一个 PowerShell，打开快约 1 秒
set "PY="
for %%P in ("%LOCALAPPDATA%\Programs\Python\Python310\pythonw.exe" "C:\Users\Administrator\AppData\Local\Programs\Python\Python310\pythonw.exe") do if not defined PY if exist %%P set "PY=%%~P"
if not defined PY for %%P in (pythonw.exe) do set "PY=%%~$PATH:P"
if not defined PY for %%P in (pyw.exe) do set "PY=%%~$PATH:P"
if not defined PY (
  echo 没找到 Python。请先安装 Python 3.10 以上版本，再运行：pip install -r requirements.txt
  pause
  exit /b 1
)
start "" "%PY%" "%~dp0boot_doctor.py"
exit /b
