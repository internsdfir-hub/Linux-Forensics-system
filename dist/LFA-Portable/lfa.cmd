@echo off
setlocal
set "LFA_HOME=%~dp0"
if "%~1"=="" (
  echo Linux Forensic Analyzer ^(portable^)
  echo.
  echo   lfa.cmd analyse --case-dir cases\CASE-001 path\to\bundle.tar.gz
  echo   lfa.cmd verify  cases\CASE-001
  echo   lfa.cmd report  cases\CASE-001
  echo.
  echo   lfa-dashboard.cmd      start the web dashboard
  echo.
  "%LFA_HOME%runtime\python.exe" -m lfa --help
  exit /b 0
)
"%LFA_HOME%runtime\python.exe" -m lfa %*
exit /b %ERRORLEVEL%
