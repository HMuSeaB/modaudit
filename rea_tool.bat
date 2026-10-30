@echo off
chcp 65001 >nul
setlocal

:: REA Android 逆向分析一键调用脚本
:: 用法: rea_tool.bat inspect <apk或apks路径>
::       rea_tool.bat search <apk路径> <类名关键字>

set SCRIPT_DIR=%~dp0
python "%SCRIPT_DIR%rea_tool.py" %*

endlocal
