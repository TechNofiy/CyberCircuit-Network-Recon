@echo off
setlocal
title CyberCircuit Network Recon V3
cd /d "%~dp0"
echo.
echo  CYBERCIRCUIT // NETWORK RECON V3
echo  Starting local defensive security dashboard...
echo.
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 app.py
  goto :done
)
where python >nul 2>nul
if %errorlevel%==0 (
  python app.py
  goto :done
)
where python3 >nul 2>nul
if %errorlevel%==0 (
  python3 app.py
  goto :done
)
echo Python was not found.
echo Install Python 3.10 or newer from https://www.python.org/downloads/
echo During setup, tick "Add Python to PATH".
start "" "https://www.python.org/downloads/"
pause
exit /b 1
:done
pause
endlocal
