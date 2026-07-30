@echo off
setlocal enabledelayedexpansion

REM --- Auto-elevacion: necesita admin para setear el DNS del sistema, el
REM --- inicio automatico, y (via la VPN) el firewall del kill switch ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Este panel necesita permisos de administrador para manejar el DNS del
    echo sistema, el inicio automatico y el firewall del kill switch de la VPN.
    echo Se va a pedir confirmacion de Windows...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" >nul 2>&1
    exit /b
)

cd /d "%~dp0"

set TASK_DASH=SecureCenterDashboardAutostart
set PYTHONW=%~dp0venv\Scripts\pythonw.exe
set PYTHON=%~dp0venv\Scripts\python.exe
set DASHBOARD_URL=http://127.0.0.1:8899/

if not exist "%PYTHON%" (
    echo.
    echo No encontre el entorno virtual ^(venv^). Antes de usar este menu, abri
    echo una consola en esta carpeta y corre una sola vez:
    echo.
    echo     python -m venv venv
    echo     venv\Scripts\activate
    echo     pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

:menu
cls
echo ================================================
echo   SecureCenter - Centro de control del stack  (admin)
echo ================================================
echo.
echo  1. Encender NUCLEO   (SecureProxy + SecureDNS + dashboard, inicio automatico)
echo  2. Apagar TODO       (nucleo + VPN si estaba + quita inicio automatico)
echo  3. Encender VPN      (todo en uno: laboratorio + aprovisionar + conectar)
echo  4. Apagar VPN
echo  5. Ver estado
echo  6. Abrir dashboard unificado
echo  7. Apagar dashboards (solo las paginas; el filtrado y el tunel siguen)
echo  8. PANICO            (revierte firewall/kill switch y apaga todo)
echo  9. Salir
echo.
echo  (todo esto tambien se maneja desde el dashboard: %DASHBOARD_URL%)
echo.
set /p opcion="Elegi una opcion (1-9): "

if "%opcion%"=="1" goto nucleo
if "%opcion%"=="2" goto apagar
if "%opcion%"=="3" goto vpn_on
if "%opcion%"=="4" goto vpn_off
if "%opcion%"=="5" goto estado
if "%opcion%"=="6" goto abrir
if "%opcion%"=="7" goto apagar_dashboards
if "%opcion%"=="8" goto panico
if "%opcion%"=="9" goto salir
goto menu

REM ---- Deja el dashboard corriendo (sin ventana, con pythonw) y registrado
REM ---- para arrancar con Windows. Usa netstat (no PowerShell) para ver si ya
REM ---- esta activo; si arranca una segunda instancia y el puerto esta tomado,
REM ---- se cierra sola: inofensivo.
:asegurar_dashboard
schtasks /create /tn "%TASK_DASH%" /tr "\"%PYTHONW%\" \"%~dp0scripts\run_dashboard.py\"" /sc onlogon /rl limited /f >nul 2>&1
netstat -an | findstr ":8899 " | findstr /I "LISTENING" >nul 2>&1
if errorlevel 1 (
    start "" "%PYTHONW%" "%~dp0scripts\run_dashboard.py"
    timeout /t 2 /nobreak >nul
)
exit /b 0

REM ---- Mata lo que escuche en el puerto pasado en %1 (sin PowerShell) ----
:matar_puerto
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%1 " ^| findstr /I "LISTENING"') do taskkill /PID %%a /F >nul 2>&1
exit /b 0

REM ---- Imprime activo/apagado para el servicio %1 en el puerto %2 (netstat) ----
:check_estado
netstat -an | findstr ":%2 " | findstr /I "LISTENING" >nul 2>&1
if errorlevel 1 (echo   %~1 : apagado) else (echo   %~1 : activo)
exit /b 0

:nucleo
echo.
echo Dejando el dashboard unificado corriendo (sin ventana, y con Windows)...
call :asegurar_dashboard
echo Encendiendo el nucleo (SecureProxy + SecureDNS)...
"%PYTHON%" scripts\start_core.py
echo.
echo Abriendo el dashboard: %DASHBOARD_URL%
start "" %DASHBOARD_URL%
pause
goto menu

:apagar
echo.
"%PYTHON%" scripts\stop_all.py
echo Deteniendo el dashboard unificado y su inicio automatico...
schtasks /delete /tn "%TASK_DASH%" /f >nul 2>&1
"%PYTHON%" scripts\stop_dashboard.py >nul 2>&1
call :matar_puerto 8899
echo.
echo Todo apagado.
pause
goto menu

:vpn_on
echo.
if not exist "C:\Program Files\WireGuard\wireguard.exe" (
    echo Falta la app oficial de WireGuard: https://www.wireguard.com/install/
    pause
    goto menu
)
call :asegurar_dashboard
"%PYTHON%" scripts\start_vpn.py
pause
goto menu

:vpn_off
echo.
"%PYTHON%" scripts\stop_vpn.py
pause
goto menu

:estado
echo.
call :check_estado "SecureProxy " 8888
call :check_estado "SecureDNS   " 8890
call :check_estado "SecureVPN   " 8891
call :check_estado "SecureCenter" 8899
echo.
schtasks /query /tn "SecureCenterCoreAutostart" >nul 2>&1
if errorlevel 1 (
    echo   Inicio con Windows del nucleo : desactivado
) else (
    echo   Inicio con Windows del nucleo : ACTIVADO
)
schtasks /query /tn "%TASK_DASH%" >nul 2>&1
if errorlevel 1 (
    echo   Inicio con Windows del panel  : desactivado
) else (
    echo   Inicio con Windows del panel  : ACTIVADO
)
echo.
pause
goto menu

:abrir
start "" %DASHBOARD_URL%
goto menu

:apagar_dashboards
echo.
echo Esto apaga SOLO las paginas web de SecureCenter y SecureVPN.
echo El filtrado (proxy y DNS) y el tunel siguen funcionando igual.
echo Los dashboards de SecureProxy y SecureDNS no se pueden apagar por
echo separado: viven dentro del mismo proceso que filtra.
echo.
"%PYTHON%" scripts\stop_dashboards.py
echo.
echo (vuelven a levantarse con la opcion 1, la 3, o en el proximo inicio
echo  de Windows si el inicio automatico sigue activado)
pause
goto menu

:panico
echo.
echo PANICO: revierte el firewall/kill switch de la VPN y apaga todo, pase lo
echo que pase. Tu PC vuelve a la normalidad.
set /p CONFIRMA="Confirmar? (s/n): "
if /i not "%CONFIRMA%"=="s" goto menu
"%PYTHON%" scripts\panic.py
schtasks /delete /tn "%TASK_DASH%" /f >nul 2>&1
"%PYTHON%" scripts\stop_dashboard.py >nul 2>&1
call :matar_puerto 8899
pause
goto menu

:salir
endlocal
exit /b 0
