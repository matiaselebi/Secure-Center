"""Chequeo de salud de cada proyecto.

Ojo con la distinción que cuesta un bug visual: **que el dashboard responda
no significa que el servicio esté haciendo su trabajo.**

- SecureProxy: el puerto que se chequea (8888) ES el proxy. Si escucha,
  está proxeando. Chequeo directo.
- SecureDNS: dashboard y resolver viven en el mismo proceso, así que si el
  dashboard responde, el resolver está arriba.
- SecureVPN: el dashboard es un proceso APARTE del túnel. Puede estar
  respondiendo con el túnel caído - de hecho es lo que pasa cuando falla el
  laboratorio. Por eso a la VPN se le pregunta su estado real por el
  endpoint /state, y se distingue "parcial" (dashboard sí, túnel no) de
  "activo" (túnel con handshake).
"""

import socket
import urllib.error
import urllib.request

from .config_loader import Config

# Estados posibles de un servicio.
APAGADO = "apagado"
PARCIAL = "parcial"  # el proceso está, pero no cumple su función todavía
ACTIVO = "activo"


def _tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


# Abridor que va DIRECTO, sin pasar por el proxy del sistema.
#
# Por qué hace falta: con el núcleo encendido, el proxy del sistema es
# SecureProxy. urllib respeta esa configuración, así que preguntarle a
# 127.0.0.1:8891 por el estado del túnel salía... por SecureProxy. Eso suma
# ruido al log del proxy y, peor, si el proxy está ocupado el chequeo de
# salud se cuelga esperando: el panel entero queda esperando a un servicio
# distinto del que estaba consultando.
_ABRIDOR_DIRECTO = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _http_text(url: str, timeout: float) -> str | None:
    try:
        with _ABRIDOR_DIRECTO.open(url, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            return resp.read(500).decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, ValueError):
        return None


def _port_for(key: str, cfg: Config) -> int | None:
    return {
        "proxy": cfg.ports.proxy_service,
        "dns": cfg.ports.dns_dashboard,
        "vpn": cfg.ports.vpn_dashboard,
    }.get(key)


def project_alive(key: str, cfg: Config, timeout: float = 1.5) -> bool:
    """¿Está corriendo el proceso de ese proyecto? (dashboard escuchando)"""
    port = _port_for(key, cfg)
    if port is None:
        return False
    return _tcp_open(cfg.dashboard_host, port, timeout)


def vpn_tunnel_state(cfg: Config, timeout: float = 1.5) -> str:
    """Estado del túnel según la propia SecureVPN (endpoint /state).

    Si el endpoint no existe (versión vieja de SecureVPN), se cae a
    "el dashboard responde" para no romper la compatibilidad."""
    port = _port_for("vpn", cfg)
    if port is None or not _tcp_open(cfg.dashboard_host, port, timeout):
        return APAGADO
    texto = _http_text(f"http://{cfg.dashboard_host}:{port}/state", timeout)
    if texto is None:
        # SecureVPN vieja, sin /state: lo único que se puede afirmar es que
        # su dashboard está arriba.
        return PARCIAL
    if "tunnel=connected" in texto:
        return ACTIVO
    return PARCIAL


def project_state(key: str, cfg: Config, timeout: float = 1.5) -> str:
    """Estado de un servicio: apagado / parcial / activo."""
    if key == "vpn":
        return vpn_tunnel_state(cfg, timeout)
    return ACTIVO if project_alive(key, cfg, timeout) else APAGADO


def health_snapshot(cfg: Config) -> dict[str, bool]:
    """Compatibilidad: True si el PROCESO está corriendo (lo que usan los
    scripts para decidir si hay algo que apagar)."""
    return {key: project_alive(key, cfg) for key in ("proxy", "dns", "vpn")}


def state_snapshot(cfg: Config) -> dict[str, str]:
    """Estado detallado de los tres, para mostrar en el dashboard."""
    return {key: project_state(key, cfg) for key in ("proxy", "dns", "vpn")}
