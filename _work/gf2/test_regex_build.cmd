@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat" >nul
if errorlevel 1 (echo VCVARS_FAIL & exit /b 1)
cd /d "%~dp0"
if not exist dist mkdir dist
cl /nologo /W3 /O2 /MT /EHsc test_safe_regex.cpp /Fe:dist\test_safe_regex.exe /Fo:dist\test_safe_regex.obj
if errorlevel 1 (echo BUILD_FAIL & exit /b 2)
dist\test_safe_regex.exe
if errorlevel 1 (echo TESTS_FAIL & exit /b 3)
echo REGEX_TEST_OK
