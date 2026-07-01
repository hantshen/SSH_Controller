@echo off
echo Installing PyInstaller if needed...
pip install pyinstaller --quiet

echo Building single EXE...
pyinstaller --onefile --windowed --name "SSH_Controller" ssh_controller.py

echo.
echo Done. EXE located at: dist\SSH_Controller.exe
pause
