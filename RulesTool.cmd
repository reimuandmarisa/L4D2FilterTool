@echo off
rem ============================================================
rem  SteamServerFilter rules tool - launcher (ASCII only!)
rem  Usage: RulesTool.cmd status ^| check ^| test ^| profiles
rem         RulesTool.cmd apply rpg+cn
rem         RulesTool.cmd restart
rem ============================================================
setlocal
set "PS1=%~dp0RulesTool.ps1"
if not exist "%PS1%" (
  echo [ERROR] RulesTool.ps1 not found next to this file.
  pause
  exit /b 1
)
where pwsh.exe >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  pwsh.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -File "%PS1%" %*
) else (
  powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -File "%PS1%" %*
)
if "%~1"=="" pause
endlocal
