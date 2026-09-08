@echo off
setlocal
echo Building who Release Win32...
call "%VS100COMNTOOLS%..\..\VC\vcvarsall.bat" x86
msbuild who.sln /t:Build /p:Configuration=Release /p:Platform=Win32
if errorlevel 1 exit /b 1

echo.
echo Building who Release x64...
call "%VS100COMNTOOLS%..\..\VC\vcvarsall.bat" amd64
msbuild who.sln /t:Build /p:Configuration=Release /p:Platform=x64
exit /b %errorlevel%
