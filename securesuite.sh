#!/usr/bin/env bash
# SecureCenter: el mismo menú que SecureCenter.bat, para Linux.
#
# POR QUÉ ES UN HERMANO Y NO UNA TRADUCCIÓN
#
# Las opciones son las mismas y hacen lo mismo porque llaman a los MISMOS
# scripts de Python. Lo único que cambia es lo que no puede ser igual: acá no
# hay UAC (se usa sudo y solo donde hace falta), no hay `netstat -ano` (se usa
# `ss`), y no hay tareas programadas (hay systemd).
#
# LO QUE NO SE INVENTA
#
# Hay dos opciones del .bat que en Linux no aplican tal cual y NO se fingen:
# la VPN depende de la app oficial de WireGuard de Windows, y el proxy del
# sistema se configura por el registro. Cuando algo no aplica, se dice; no se
# muestra un botón que no hace nada. Es la misma regla que sigue el panel.

set -uo pipefail

CARPETA="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$CARPETA" || exit 1

PYTHON="$CARPETA/venv/bin/python"
DASHBOARD_URL="http://127.0.0.1:8899/"
UNIDAD_PANEL="securecenter-dashboard-autostart.service"

# El usuario, con red de contención. `$USER` parece siempre estar, pero no lo
# está: en una sesión lanzada por systemd, por cron o dentro de un contenedor
# el entorno viene casi vacío, y con `set -u` la primera vez que se lo nombra
# el script muere entero. Apareció corriendo esto de verdad.
USUARIO="${USER:-${LOGNAME:-$(id -un 2>/dev/null || echo usuario)}}"

if [[ ! -x "$PYTHON" ]]; then
    cat <<FIN

No encontré el entorno virtual (venv). Antes de usar este menú, abrí una
consola en esta carpeta y corré una sola vez:

    python3 -m venv venv
    venv/bin/pip install -r requirements.txt

FIN
    exit 1
fi

# ---------------------------------------------------------------- ayudantes

# ¿Hay algo escuchando en este puerto? Se usa `ss`, que es lo estándar hoy, y
# se cae a `netstat` en sistemas viejos. Mismo criterio que procutil.py, para
# que el menú y el panel nunca digan cosas distintas del mismo puerto.
puerto_activo() {
    local puerto="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | grep -q ":${puerto} "
    elif command -v netstat >/dev/null 2>&1; then
        netstat -ltn 2>/dev/null | grep -q ":${puerto} "
    else
        return 1
    fi
}

estado_de() {
    if puerto_activo "$2"; then
        printf '  %-13s: activo\n' "$1"
    else
        printf '  %-13s: apagado\n' "$1"
    fi
}

matar_puerto() {
    local puerto="$1" pids
    pids="$(ss -ltnp 2>/dev/null | grep ":${puerto} " | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u)"
    for pid in $pids; do
        kill -9 "$pid" 2>/dev/null
    done
}

abrir_navegador() {
    # En un servidor sin escritorio no hay navegador, y eso no es un error:
    # se imprime la dirección y listo.
    if command -v xdg-open >/dev/null 2>&1 && [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
        xdg-open "$DASHBOARD_URL" >/dev/null 2>&1 &
    else
        echo "Abrí esta dirección en tu navegador: $DASHBOARD_URL"
    fi
}

# Deja el panel corriendo. Equivale al :asegurar_dashboard del .bat.
asegurar_panel() {
    if ! puerto_activo 8899; then
        nohup "$PYTHON" "$CARPETA/scripts/run_dashboard.py" >/dev/null 2>&1 &
        sleep 2
    fi
}

pausa() {
    echo
    read -r -p "Enter para volver al menú..." _
}

# --------------------------------------------------------------------- menú

menu() {
    clear
    local usuario_linger="no"
    if command -v loginctl >/dev/null 2>&1; then
        loginctl show-user "$USUARIO" --property=Linger 2>/dev/null | grep -q "Linger=yes" && usuario_linger="sí"
    fi

    cat <<FIN
================================================
  SecureCenter - Centro de control del stack
================================================

 1. Encender NUCLEO   (todo menos la VPN: Proxy, DNS, HIPS, Intel,
                       Scanner, Agent y los paneles)
 2. Apagar TODO       (núcleo + quita el arranque automático)
 3. Ver estado
 4. Abrir panel unificado
 5. Apagar paneles (solo las páginas; el filtrado y la vigilancia siguen)
 6. PANICO            (revierte el firewall y apaga todo)
 7. Salir

 (todo esto también se maneja desde el panel: $DASHBOARD_URL)
FIN

    if [[ "$usuario_linger" == "no" ]]; then
        cat <<FIN

 AVISO: tu usuario no tiene "linger" activado, así que los servicios que
 arrancan solos NO van a levantar hasta que inicies sesión. En un servidor
 sin pantalla eso significa que no levantan nunca. Se arregla con:

     sudo loginctl enable-linger $USUARIO
FIN
    fi
    echo
    # Enter sin escribir nada no hace nada: `opcion` queda vacía y cae en el
    # `*)` de abajo. En el .bat esto era un bug de verdad, porque la variable
    # conservaba el valor de la vuelta anterior.
    opcion=""
    read -r -p "Elegí una opción (1-7): " opcion
    echo

    case "$opcion" in
        1) nucleo ;;
        2) apagar ;;
        3) estado ;;
        4) abrir_navegador ;;
        5) apagar_paneles ;;
        6) panico ;;
        7) exit 0 ;;
        *) ;;
    esac
}

nucleo() {
    echo "Dejando el panel unificado corriendo..."
    asegurar_panel
    echo "Encendiendo el núcleo (todo menos la VPN)..."
    "$PYTHON" scripts/start_core.py
    echo
    abrir_navegador
    pausa
}

apagar() {
    "$PYTHON" scripts/stop_all.py
    echo "Deteniendo el panel unificado y su arranque automático..."
    systemctl --user disable --now "$UNIDAD_PANEL" >/dev/null 2>&1
    "$PYTHON" scripts/stop_dashboard.py >/dev/null 2>&1
    matar_puerto 8899
    echo
    echo "Todo apagado."
    pausa
}

estado() {
    estado_de "SecureProxy" 8888
    estado_de "SecureDNS" 8890
    estado_de "SecureVPN" 8891
    estado_de "SecureHIPS" 8892
    estado_de "Secure-Intel" 8893
    estado_de "Secure-Scanner" 8894
    estado_de "Secure-Agent" 8895
    estado_de "SecureCenter" 8899
    echo
    if systemctl --user is-enabled securecenter-core-autostart.service >/dev/null 2>&1; then
        echo "  Arranque automático del núcleo : ACTIVADO"
    else
        echo "  Arranque automático del núcleo : desactivado"
    fi
    echo
    # Lo que en este equipo no aplica, dicho de frente. Sale de capacidades.py
    # y no de un texto escrito acá: si mañana cambia lo que aplica, el menú se
    # entera solo. Dos textos que se contradicen es peor que uno solo.
    "$PYTHON" -c "
import sys; sys.path.insert(0, 'src')
from securecenter import capacidades
for c in capacidades.todas():
    marca = {'ok': ' ok  ', 'aviso': 'AVISO', 'na': 'n/a  '}.get(c['estado'], '     ')
    print(f'  [{marca}] {c[\"nombre\"]}: {c[\"detalle\"]}')
" 2>/dev/null || echo "  (no pude leer las capacidades)"
    pausa
}

apagar_paneles() {
    cat <<'FIN'
Esto apaga las páginas web de SecureCenter y Secure-Intel. El filtrado
(proxy y DNS) y la vigilancia del HIPS siguen funcionando igual.

En Secure-Intel el panel es casi todo el proceso, así que se apaga entero.
No pasa nada: los feeds que ya bajó siguen en su lugar y los otros los leen
igual. Lo único que se pierde es que se pongan al día solos.

Los paneles de SecureProxy, SecureDNS y SecureHIPS NO se pueden apagar por
separado: viven dentro del mismo proceso que hace el trabajo. Apagar el del
HIPS sería apagar la vigilancia y encima dejarle las reglas puestas en el
firewall.
FIN
    echo
    "$PYTHON" scripts/stop_dashboards.py
    pausa
}

panico() {
    cat <<'FIN'
PANICO: revierte el firewall y apaga todo, pase lo que pase. La máquina
vuelve a la normalidad.
FIN
    read -r -p "Confirmar? (s/n): " confirma
    if [[ "${confirma,,}" != "s" ]]; then
        return
    fi
    "$PYTHON" scripts/panic.py
    systemctl --user disable --now "$UNIDAD_PANEL" >/dev/null 2>&1
    "$PYTHON" scripts/stop_dashboard.py >/dev/null 2>&1
    matar_puerto 8899
    pausa
}

while true; do
    menu
done
