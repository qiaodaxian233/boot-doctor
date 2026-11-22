@echo off
chcp 936 >nul
cd /d "%~dp0"
set PY=C:\Users\Administrator\AppData\Local\Programs\Python\Python310\python.exe
if not exist "%PY%" set PY=python
"%PY%" "%~dp0undelay.py" %*
if "%~1"=="" pause
