@echo off
REM Launcher for PRISM - installs dependencies (if missing) and runs the tool.
SET SCRIPT_DIR=%~dp0

python -c "import rich, yaml" 2>NUL
IF ERRORLEVEL 1 (
    echo Installing dependencies...
    pip install -r "%SCRIPT_DIR%requirements.txt"
)

python "%SCRIPT_DIR%prism.py" %*
