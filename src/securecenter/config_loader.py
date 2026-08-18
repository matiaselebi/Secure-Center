"""Configuración de SecureCenter.

SecureCenter no reimplementa nada de los proyectos administrados: los orquesta. Para
eso necesita saber DÓNDE están en el disco. Por defecto los busca solo (son
carpetas hermanas dentro de la misma carpeta de proyectos), pero todo se
puede fijar a mano en config/config.yaml si los tenés en otro lado.
"""

import ipaddress
from dataclasses import dataclass, field, fields
from pathlib import Path

import yaml

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


@dataclass
class ProjectPaths:
    """Ruta a cada proyecto. Vacío ("") = autodetectar entre las carpetas
    hermanas buscando su paquete característico (src/secureproxy, etc.)."""

    proxy: str = ""
    dns: str = ""
    vpn: str = ""
    hips: str = ""
    intel: str = ""
    scanner: str = ""
    agente: str = ""


@dataclass
class Ports:
    """Puertos de cada proyecto.

    Ojo con SecureProxy: tiene DOS puertos. El 8888 es por donde proxea (es
    el que dice si el servicio está vivo y el que hay que liberar para
    apagarlo) y el 8889 es su dashboard, que vive en su propio puerto.
    SecureDNS, SecureVPN, SecureHIPS y Secure-Intel usan un solo puerto."""

    proxy_service: int = 8888
    proxy_dashboard: int = 8889
    dns_dashboard: int = 8890
    vpn_dashboard: int = 8891
    hips_dashboard: int = 8892
    intel_dashboard: int = 8893
    scanner_dashboard: int = 8894
    # Secure-Agent tiene DOS puertos: el 8895 recibe de los agentes y es
    # el único de la suite abierto a la LAN; el 8896 es su panel, que
    # escucha solo en loopback como todos los demás.
    agente_ingesta: int = 8895
    agente_dashboard: int = 8896
    center_dashboard: int = 8899

    def __post_init__(self) -> None:
        for campo in fields(self):
            valor = getattr(self, campo.name)
            if isinstance(valor, bool) or not isinstance(valor, int) or not 1 <= valor <= 65535:
                raise ValueError(
                    f"puerto inválido para {campo.name}: {valor!r} (debe ser 1..65535)")


@dataclass
class Externos:
    """Motores que no son proyectos de la suite pero cuyos datos sí entran.

    Pi-hole no tiene carpeta hermana, ni venv, ni script de arranque: es un
    servicio instalado en el sistema. Por eso va por ruta absoluta y no por la
    autodetección de `ProjectPaths`.

    Vacío = no está, y no se intenta leer nada. Lo único que hace SecureCenter
    con esta base es leerla, en modo solo lectura.
    """

    pihole_db: str = ""
    # La salida de Suricata. Misma forma que Pi-hole: un motor del sistema,
    # por ruta absoluta, y SecureCenter solo lo lee. Vacío = no está.
    suricata_eve: str = ""
    # Solo se usa para saber si está en modo IPS, que es lo que la fase 1 del
    # punto 9 no quiere. Se lee parseado, nunca buscando texto: el archivo que
    # trae el paquete está lleno de ejemplos comentados.
    suricata_yaml: str = "/etc/suricata/suricata.yaml"


@dataclass
class ArranqueConfig:
    """Cómo se deja el núcleo arrancando solo. Solo aplica en Linux.

    En Windows es siempre una tarea programada `onlogon` y no hay nada que
    elegir. En Linux hay dos formas y la diferencia importa:

    - `usuario`: unidad en `~/.config/systemd/user/`, sin root. Es lo correcto
      en una máquina de escritorio. Necesita `loginctl enable-linger` para
      arrancar en un servidor donde nadie inicia sesión, y SecureCenter avisa
      si falta.
    - `sistema`: unidad en `/etc/systemd/system/`, arranca en el boot sin que
      nadie entre. Necesita root. Es lo que va a querer el servidor de Debian.
    """

    alcance: str = "usuario"


@dataclass
class Config:
    paths: ProjectPaths = field(default_factory=ProjectPaths)
    ports: Ports = field(default_factory=Ports)
    externos: Externos = field(default_factory=Externos)
    arranque: ArranqueConfig = field(default_factory=ArranqueConfig)
    # Host donde escucha el dashboard unificado (loopback: solo tu PC).
    dashboard_host: str = "127.0.0.1"
    # DB propia de SecureCenter (eventos de orquestación: encendidos, apagados).
    db_path: str = "data/center_logs.db"

    def resolve_path(self, relative_path: str) -> Path:
        path = Path(relative_path)
        return path if path.is_absolute() else PROJECT_ROOT / path


def load_config(config_path: str | None = None) -> Config:
    if config_path is None:
        config_path = str(PROJECT_ROOT / "config" / "config.yaml")

    # Los secretos salen del entorno, nunca del YAML. Es la regla de toda la
    # suite. Acá hay uno solo: SECUREHIPS_API_TOKEN, que habilita pedirle un
    # bloqueo a SecureHIPS desde un incidente (fase 4 del punto 9). Tiene que
    # ser el MISMO string que el del .env de SecureHIPS; se copia a mano una
    # vez, no hay intercambio de credenciales entre los proyectos.
    if load_dotenv is not None:
        load_dotenv(PROJECT_ROOT / ".env")

    raw: dict = {}
    if Path(config_path).exists():
        with open(config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

    # El panel no tiene login: su frontera de seguridad es loopback. Exponerlo
    # en 0.0.0.0 convierte Host/Origin en defensas auxiliares, no autenticación.
    dashboard_host = str(raw.get("dashboard_host", "127.0.0.1")).strip()
    try:
        es_loopback = ipaddress.ip_address(dashboard_host.strip("[]")).is_loopback
    except ValueError:
        es_loopback = dashboard_host.lower() == "localhost"
    if not es_loopback:
        raise ValueError(
            "dashboard_host debe ser loopback (127.0.0.1, ::1 o localhost); "
            "SecureCenter no tiene autenticación para exponerse a la red")

    # db_path acepta la forma de los hermanos (logging: db_path) o al ras.
    db_path = raw.get("logging", {}).get("db_path") or raw.get("db_path", "data/center_logs.db")
    return Config(
        paths=ProjectPaths(**raw.get("paths", {})),
        ports=Ports(**raw.get("ports", {})),
        externos=Externos(**(raw.get("externos") or {})),
        arranque=ArranqueConfig(**(raw.get("arranque") or {})),
        dashboard_host=dashboard_host,
        db_path=db_path,
    )
