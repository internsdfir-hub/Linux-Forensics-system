@echo off
setlocal
set "LFA_HOME=%~dp0"
echo Checking the portable LFA install...
"%LFA_HOME%runtime\python.exe" -c "import sys, sqlite3, ssl, zoneinfo, yaml, jinja2, lfa; print('python     ', sys.version.split()[0]); print('sqlite3    ', sqlite3.sqlite_version); print('ssl        ', ssl.OPENSSL_VERSION.split()[1]); print('PyYAML     ', yaml.__version__); print('Jinja2     ', jinja2.__version__); print('timezones  ', len(zoneinfo.available_timezones()), 'available'); print(); print('OK - portable LFA is functional.')"
if errorlevel 1 echo FAILED - the install is incomplete.
pause
