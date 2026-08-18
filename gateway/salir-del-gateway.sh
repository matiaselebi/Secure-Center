#!/usr/bin/env bash
#
# Volver atrás: que esta máquina deje de ser el router de la casa.
#
# ============================ POR QUÉ EXISTE ============================
#
# La fase 3 del punto 10 dice: "un plan de salida escrito y probado. Si no lo
# probaste, no lo tenés". Este archivo es la parte escrita, y el modo
# --simulacro es la parte probada.
#
# Un plan de salida que nunca corrió es una hoja de papel. Lo que falla al
# volver atrás son siempre las mismas cosas y ninguna se ve leyendo:
#
#   - El router del proveedor tiene el DHCP apagado hace seis meses y nadie
#     se acuerda de la clave del panel.
#   - El cable no alcanza porque el servidor se movió de lugar.
#   - systemd-networkd quedó sin `enable` y al reiniciar no levanta.
#
# Todas esas se descubren la primera vez que lo hacés. La única pregunta es si
# esa primera vez es un martes a la tarde con tiempo, o un domingo a la noche
# con la casa sin internet y alguien mirándote.
#
# ============================== LOS MODOS ==============================
#
#   --ver         (por defecto) muestra qué haría. No toca NADA.
#   --salir       lo hace de verdad: saca el gateway.
#   --volver      vuelve a poner el gateway.
#   --simulacro   salir, esperar a que confirmes que la casa anda, y volver.
#                 Es LO que hay que correr, y es lo único que deja la marca
#                 que el diagnóstico mira.
#
# ============================ ANTES DE CORRER ===========================
#
# Corré esto SENTADO AL LADO DEL SERVIDOR, con teclado y pantalla, no por SSH.
# Sacar el gateway te puede cortar tu propia sesión, y ahí quedás sin manos.
#
# Y tené a mano, escrito en papel o en el celular:
#   - cómo se entra al panel del router del proveedor (IP y clave)
#   - dónde va enchufado cada cable
#
set -uo pipefail

MODO="${1:---ver}"
RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MARCA="$RAIZ/data/ultimo-simulacro-gateway"

# Los cuatro archivos de la fase 1, con su destino.
declare -a DESTINOS=(
    "/etc/nftables.d/gateway.conf"
    "/etc/sysctl.d/99-gateway.conf"
    "/etc/dnsmasq.d/gateway.conf"
    "/etc/systemd/network/10-lan.network"
)
declare -a ORIGENES=(
    "$RAIZ/gateway/nftables-gateway.conf"
    "$RAIZ/gateway/99-gateway.conf"
    "$RAIZ/gateway/dnsmasq-gateway.conf"
    "$RAIZ/gateway/10-lan.network"
)

VER_SOLAMENTE=1

decir() { printf '%s\n' "$*"; }
titulo() { printf '\n=== %s ===\n' "$*"; }

# Corre un comando, o lo muestra. Nunca corta el script: en un plan de salida,
# que un paso falle no puede impedir los siguientes. Si el `rm` de un archivo
# falla porque no estaba, los otros tres se tienen que borrar igual.
hacer() {
    if [ "$VER_SOLAMENTE" -eq 1 ]; then
        decir "   [ver]  $*"
        return 0
    fi
    decir "   ---->  $*"
    if "$@"; then
        return 0
    fi
    decir "          (falló, sigo con lo que queda)"
    return 0
}

salir_del_gateway() {
    titulo "Sacando el gateway"

    decir "1. La tabla de NAT. SecureHIPS no se toca: es otra tabla."
    hacer nft delete table inet gateway

    decir "2. El reenvío de paquetes."
    for destino in "/etc/sysctl.d/99-gateway.conf" "/etc/nftables.d/gateway.conf"; do
        hacer rm -f "$destino"
    done
    hacer sysctl -w net.ipv4.ip_forward=0

    decir "3. El DHCP. A partir de acá esta máquina no reparte más IPs."
    hacer rm -f /etc/dnsmasq.d/gateway.conf
    hacer systemctl restart pihole-FTL

    decir "4. La IP fija de la interfaz de la casa."
    hacer rm -f /etc/systemd/network/10-lan.network
    hacer systemctl restart systemd-networkd

    titulo "AHORA, A MANO"
    decir "  a) Volvé a prender el DHCP en el router del proveedor."
    decir "  b) Pasá el cable de la casa del servidor al router."
    decir "  c) En cada equipo: desconectar y reconectar el wifi, o reiniciar."
    decir ""
    decir "  Los equipos van a seguir con la IP vieja hasta que se les venza"
    decir "  el lease (12 horas). No esperes: reconectalos."
}

volver_al_gateway() {
    titulo "Volviendo a poner el gateway"
    local i
    for i in "${!DESTINOS[@]}"; do
        hacer cp "${ORIGENES[$i]}" "${DESTINOS[$i]}"
    done
    hacer sysctl --system
    hacer nft -f "$RAIZ/gateway/nftables-gateway.conf"
    hacer systemctl restart systemd-networkd
    hacer systemctl restart pihole-FTL
    decir ""
    decir "  Y apagá de nuevo el DHCP del router del proveedor."
}

marcar_simulacro() {
    mkdir -p "$(dirname "$MARCA")"
    printf '%s %s\n' "$(date +%s)" "$(date -Iseconds)" > "$MARCA"
    decir ""
    decir "Anotado en $MARCA."
    decir "El diagnóstico de SecureCenter lo va a ver y va a dejar de marcarlo en rojo."
}

case "$MODO" in
    --ver)
        VER_SOLAMENTE=1
        decir "MODO VER: no se toca nada. Esto es lo que haría."
        salir_del_gateway
        decir ""
        decir "Para hacerlo de verdad:      sudo bash $0 --salir"
        decir "Para probarlo y volver:      sudo bash $0 --simulacro"
        ;;
    --salir)
        VER_SOLAMENTE=0
        salir_del_gateway
        ;;
    --volver)
        VER_SOLAMENTE=0
        volver_al_gateway
        ;;
    --simulacro)
        VER_SOLAMENTE=0
        decir "SIMULACRO. Se saca el gateway de verdad y después se vuelve a poner."
        decir "Hacelo sentado al lado del servidor, no por SSH."
        decir ""
        read -r -p "¿Seguimos? [s/N] " respuesta
        case "$respuesta" in
            s|S|si|SI|Si) ;;
            *) decir "Cancelado. No se tocó nada."; exit 0 ;;
        esac

        salir_del_gateway

        titulo "AHORA PROBÁ DE VERDAD"
        decir "No sigas hasta que hayas comprobado, en un equipo real:"
        decir "  1. que agarra IP del router del proveedor"
        decir "  2. que abre una página"
        decir ""
        decir "Si algo de eso no anda, ESTE es el momento de descubrirlo. Anotá qué"
        decir "faltó: eso es lo que este simulacro vino a encontrar."
        decir ""
        read -r -p "¿La casa tiene internet sin el gateway? [s/N] " anduvo

        volver_al_gateway

        case "$anduvo" in
            s|S|si|SI|Si)
                marcar_simulacro
                ;;
            *)
                decir ""
                decir "NO se anota el simulacro, porque no salió bien."
                decir "Un simulacro que no funcionó no cuenta como plan probado:"
                decir "eso es exactamente lo que dice la fase 3."
                exit 1
                ;;
        esac
        ;;
    *)
        decir "Modo desconocido: $MODO"
        decir "Usá: --ver | --salir | --volver | --simulacro"
        exit 2
        ;;
esac
