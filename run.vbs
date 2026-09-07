Set WshShell = CreateObject("WScript.Shell")
curDir = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
WshShell.CurrentDirectory = curDir
WshShell.Run "pythonw """ & curDir & "\app_gui.py""", 0, False
