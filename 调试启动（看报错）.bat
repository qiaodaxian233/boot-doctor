@echo off
chcp 936 >nul
cd /d "%~dp0"
rem 调试模式保持原样：普通权限、带控制台，方便看报错
set BOOTDOC_NO_ELEVATE=1
set "PY="
for %%P in ("%LOCALAPPDATA%\Programs\Python\Python310\python.exe" "C:\Users\Administrator\AppData\Local\Programs\Python\Python310\python.exe") do if not defined PY if exist %%P set "PY=%%~P"
if not defined PY for %%P in (python.exe) do set "PY=%%~$PATH:P"
if not defined PY for %%P in (py.exe) do set "PY=%%~$PATH:P"
if not defined PY set "PY=python"
"%PY%" "%~dp0boot_doctor.py"
echo.
echo ---- 程序已退出，按任意键关闭 ----
pause >nul
