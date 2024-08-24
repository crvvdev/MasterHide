@echo off

set SOURCE_PATH=%~dp0\KasperskyHook\klhk\klhk.sys
set DESTINATION_PATH=%SystemRoot%\System32\Drivers\klhk.sys

if not exist "%SOURCE_PATH%" (
    echo Source file not found: %SOURCE_PATH%
    pause
    exit /b 1
)

copy "%SOURCE_PATH%" "%DESTINATION_PATH%" /Y

if %ERRORLEVEL% equ 0 (
    echo File copied successfully to %DESTINATION_PATH%
) else (
    echo Failed to move the file
    pause
    exit /b 1
)

pause
exit /b 0