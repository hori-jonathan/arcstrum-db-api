@echo off
REM Auto build script for db-api (CMake, Crow, Asio, nlohmann/json)

REM Remove old build folder
IF EXIST build (
    rmdir /s /q build
)

REM Make new build folder
mkdir build
cd build

REM Run CMake configuration
cmake ..

IF %ERRORLEVEL% NEQ 0 (
    echo CMake configuration failed!
    pause
    exit /b %ERRORLEVEL%
)

REM Build the project
cmake --build .

IF %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    pause
    exit /b %ERRORLEVEL%
)

cd ..

REM Optionally, prompt to run
echo.
echo Build succeeded!
echo.
set /p RUNNOW="Run db-api now? (y/n): "
if /i "%RUNNOW%"=="y" (
    .\build\db-api.exe
)
