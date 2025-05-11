@echo off
echo Resetting database and migrations...

REM Remove database file
if exist instance\app.db (
    del /f instance\app.db
    echo Removed database file
)

REM Remove migrations directory
if exist migrations (
    rmdir /s /q migrations
    echo Removed migrations directory
)

REM Create instance directory
if not exist instance (
    mkdir instance
    echo Created instance directory
)

echo.
echo Running migrations...
echo.

REM Initialize migrations
call .\venv\Scripts\python.exe -m flask db init
echo.

REM Create migration
call .\venv\Scripts\python.exe -m flask db migrate
echo.

REM Apply migration
call .\venv\Scripts\python.exe -m flask db upgrade
echo.

echo Done! 