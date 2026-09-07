@echo off
cd /d "%~dp0"
start "" "%LOCALAPPDATA%\..\..\scoop\apps\python\current\pythonw.exe" "app_gui.py" %*
