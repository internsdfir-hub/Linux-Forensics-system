@echo off
setlocal
set "LFA_HOME=%~dp0"
if "%~1"=="" (
  echo Usage: lfa-server.cmd ^<token^> [port]
  echo.
  echo   Starts the ingestion server on ALL interfaces so a Linux
  echo   target can stream evidence to it:
  echo.
  echo     sudo sh collect.sh -c CASE-01 -p Bob -M ^\
  echo          -s http://THIS-HOST:8443 -T ^<token^>
  echo.
  echo   The collector appends /api/v1/ingest to the URL itself.
  echo   This is plain HTTP. For TLS, run lfa.cmd serve directly
  echo   with --cert and --key ^(no certificate is generated for you^).
  exit /b 2
)
set "LFA_TOKEN=%~1"
set "LFA_PORT=%~2"
if "%LFA_PORT%"=="" set "LFA_PORT=8443"
echo Listening for streamed evidence on 0.0.0.0:%LFA_PORT% (plain HTTP)
echo Ingest endpoint: http://^<this-host^>:%LFA_PORT%/api/v1/ingest
echo Dashboard:       http://127.0.0.1:%LFA_PORT%
echo Press Ctrl+C to stop.
echo.
"%LFA_HOME%runtime\python.exe" -m lfa serve --host 0.0.0.0 --port %LFA_PORT% --token "%LFA_TOKEN%" --cases-dir "%LFA_HOME%cases"
exit /b %ERRORLEVEL%
