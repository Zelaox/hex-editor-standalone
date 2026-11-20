@echo off
setlocal
set "HEX_PYTHON=%~dp0.venv\Scripts\python.exe"
if not exist "%HEX_PYTHON%" set "HEX_PYTHON=python"
"%HEX_PYTHON%" -B "%~dp0main.py" %*
