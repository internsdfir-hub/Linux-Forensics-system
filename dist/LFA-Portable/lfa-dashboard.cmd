@echo off
setlocal
set "LFA_HOME=%~dp0"
set LFA_PORT=8443
echo Starting LFA dashboard (local review, loopback only)
echo   http://127.0.0.1:%LFA_PORT%
echo Press Ctrl+C to stop.
echo.
"%LFA_HOME%runtime\python.exe" -m lfa serve --host 127.0.0.1 --port %LFA_PORT% --cases-dir "%LFA_HOME%cases" %*
exit /b %ERRORLEVEL%
