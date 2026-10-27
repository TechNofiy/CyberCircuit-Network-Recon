@echo off
setlocal
cd /d "%~dp0"
echo CyberCircuit Network Recon V5 - syntax and test check
py -3 -m py_compile app.py plugins\*.py
if errorlevel 1 (
  echo Python syntax check failed.
  pause
  exit /b 1
)
py -3 -m unittest discover -s tests -v
if errorlevel 1 (
  echo Tests failed.
  pause
  exit /b 1
)
echo Build checks passed. This Python app runs from source; no installer is produced.
pause
