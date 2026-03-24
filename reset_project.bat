@echo off
echo ===================================================
echo     DDoS Attack Detector - Factory Reset
echo ===================================================
echo.
echo Stopping any running Python processes...
taskkill /F /IM python.exe /T >nul 2>&1
echo.
echo Deleting SQLite database...
if exist "db.sqlite3" del /Q "db.sqlite3"
echo.
echo Removing old migrations...
for /d %%x in (detection\migrations\*) do (
    if /I "%%~nx" NEQ "__init__.py" if /I "%%~nx" NEQ "__pycache__" (
        rmdir /S /Q "%%x" >nul 2>&1
    )
)
del /Q /S "detection\migrations\*.py" >nul 2>&1
echo.> "detection\migrations\__init__.py"
echo.
echo Making new migrations...
python manage.py makemigrations detection
echo.
echo Applying migrations...
python manage.py migrate
echo.
echo Starting the web server...
start "Django Server" cmd /k "python manage.py runserver"
echo.
echo Waiting for server to start...
timeout /t 5 /nobreak
echo.
:: echo Starting Traffic Simulator...
:: start "Traffic Simulator" cmd /k "python continuous_traffic.py"
:: echo.
echo Opening Browser to Dashboard...
start http://127.0.0.1:8000/
echo.
echo ===================================================
echo     Project reset and started successfully!
echo ===================================================
pause
