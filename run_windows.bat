@echo off
setlocal EnableExtensions
cd /d "%~dp0"

where py >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Python Launcher ^(py^) was not found.
  echo Install Python 3.12 from https://www.python.org/downloads/windows/
  echo Make sure the Python Launcher is installed, then run this file again.
  pause
  exit /b 1
)

py -3.12 --version >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Python 3.12 is required for the supported Windows setup.
  echo Install Python 3.12 from https://www.python.org/downloads/windows/
  pause
  exit /b 1
)

if not exist "%~dp0.venv\Scripts\python.exe" (
  echo [Setup] Creating a project-local Python environment...
  py -3.12 -m venv "%~dp0.venv"
  if errorlevel 1 (
    echo [ERROR] Could not create the virtual environment.
    pause
    exit /b 1
  )
)

set "APP_PYTHON=%~dp0.venv\Scripts\python.exe"

echo [Setup] Installing or verifying project dependencies...
"%APP_PYTHON%" -m pip install --disable-pip-version-check -r "%~dp0requirements.txt"
if errorlevel 1 (
  echo [ERROR] Dependency installation failed. Check the messages above, then retry.
  pause
  exit /b 1
)

"%APP_PYTHON%" -c "import tldextract; print('[Setup] Public-suffix scope dependency: OK')"
if errorlevel 1 (
  echo [ERROR] tldextract did not install correctly. Subdomain scope verification was not started.
  pause
  exit /b 1
)

echo [Launch] Starting Recon-GUI...
"%APP_PYTHON%" "%~dp0main.py" %*
set "APP_EXIT_CODE=%ERRORLEVEL%"

if not "%APP_EXIT_CODE%"=="0" (
  echo.
  echo [ERROR] Recon-GUI exited with code %APP_EXIT_CODE%.
  pause
)

exit /b %APP_EXIT_CODE%
