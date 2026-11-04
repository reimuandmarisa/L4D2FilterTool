@echo off
setlocal
cd /d "%~dp0"
set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
if not exist "%VCVARS%" set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars32.bat"
if not exist "%VCVARS%" set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars32.bat"
if not exist "%VCVARS%" set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VCVARS%" if exist "%VSWHERE%" for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VCVARS=%%i\VC\Auxiliary\Build\vcvars32.bat"
if not exist "%VCVARS%" (echo VCVARS_FAILED & exit /b 1)
call "%VCVARS%" >nul 2>nul
if errorlevel 1 (echo VCVARS_FAILED & exit /b 1)
if not exist dist mkdir dist
cl /nologo /W3 /O2 /MT /EHsc /DUNICODE /D_UNICODE ssf_group_filter2.cpp /link /DLL /OUT:dist\SSF_GroupFilter2.dll /PDB:dist\SSF_GroupFilter2.pdb /MAP:dist\SSF_GroupFilter2.map bcrypt.lib user32.lib advapi32.lib
if errorlevel 1 (echo DLL_BUILD_FAILED & exit /b 2)
cl /nologo /W3 /O2 /MT /EHsc /DUNICODE /D_UNICODE ssf_group_injector.cpp /link /OUT:dist\ssf-group-injector.exe /PDB:dist\ssf-group-injector.pdb bcrypt.lib user32.lib
if errorlevel 1 (echo INJECTOR_BUILD_FAILED & exit /b 3)
echo BUILD_OK
