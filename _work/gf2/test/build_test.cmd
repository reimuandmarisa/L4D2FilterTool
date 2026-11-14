@echo off
call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat" >nul
cd /d "%~dp0"
cl /nologo /EHsc /utf-8 /O2 test_regex.cpp /Fe:test_regex.exe
if exist test_regex.exe (echo TESTBUILD_OK) else (echo TESTBUILD_FAIL)
