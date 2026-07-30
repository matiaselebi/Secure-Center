"""Modelo de cada proyecto administrado y su autodetección.

Cada proyecto (SecureProxy, SecureDNS, SecureVPN) se describe con lo mínimo
que SecureCenter necesita para orquestarlo sin tocar su código: dónde está
su carpeta, qué intérprete de su venv usar, y cuál es su paquete
característico (para encontrarlo solo entre las carpetas hermanas).
"""

import platform
from dataclasses import dataclass
from pathlib import Path

from .config_loader import Config, ProjectPaths


@dataclass(frozen=True)
class ProjectSpec:
    key: str  # "proxy" | "dns" | "vpn"
    display_name: str
    package: str  # paquete en src/ que lo identifica (marcador de autodetección)
    role: str  # descripción corta para el dashboard
    dashboard_path: str  # ruta del dashboard de ese proyecto (¡no todos usan "/"!)


PROJECT_SPECS: tuple[ProjectSpec, ...] = (
    # Los tres sirven su panel en la raíz de su puerto de dashboard.
    ProjectSpec("proxy", "SecureProxy", "secureproxy", "filtro de conexiones", "/"),
    ProjectSpec("dns", "SecureDNS", "securedns", "filtro de nombres", "/"),
    ProjectSpec("vpn", "SecureVPN", "securevpn", "transporte cifrado", "/"),
)


def _looks_like_project(folder: Path, package: str) -> bool:
    """Una carpeta ES un proyecto si tiene su paquete en src/ (marcador
    estable, no depende de cómo se llame la carpeta)."""
    return (folder / "src" / package).is_dir()


def autodetect_project(package: str, search_root: Path) -> Path | None:
    """Busca la carpeta de un proyecto entre las subcarpetas de search_root
    (la carpeta que contiene a SecureCenter y a sus hermanos)."""
    if not search_root.is_dir():
        return None
    for child in sorted(search_root.iterdir()):
        if child.is_dir() and _looks_like_project(child, package):
            return child
    return None


class ManagedProject:
    def __init__(self, spec: ProjectSpec, folder: Path | None):
        self.spec = spec
        self.folder = folder  # None si no se encontró

    @property
    def found(self) -> bool:
        return self.folder is not None and self.folder.is_dir()

    def venv_python(self, *, windowless: bool = False) -> Path | None:
        """Intérprete del venv del proyecto. windowless=True usa pythonw.exe
        en Windows (arranca el proceso sin ventana de consola)."""
        if self.folder is None:
            return None
        if platform.system() == "Windows":
            exe = "pythonw.exe" if windowless else "python.exe"
            return self.folder / "venv" / "Scripts" / exe
        return self.folder / "venv" / "bin" / "python"

    def script(self, relative: str) -> Path | None:
        return None if self.folder is None else self.folder / relative

    def db_path(self, relative: str) -> Path | None:
        return None if self.folder is None else self.folder / relative


def discover_projects(cfg: Config, search_root: Path | None = None) -> dict[str, ManagedProject]:
    """Arma el mapa key -> ManagedProject, usando primero la ruta explícita
    del config.yaml y, si está vacía, autodetectando entre las hermanas.

    search_root por defecto es la carpeta que contiene a SecureCenter (ahí
    viven los tres proyectos, cada uno en su carpeta, según tu setup)."""
    if search_root is None:
        from .config_loader import PROJECT_ROOT

        search_root = PROJECT_ROOT.parent
    search_root = Path(search_root)  # tolera recibir un str

    configured: ProjectPaths = cfg.paths
    result: dict[str, ManagedProject] = {}
    for spec in PROJECT_SPECS:
        explicit = getattr(configured, spec.key, "") or ""
        folder: Path | None
        if explicit:
            folder = cfg.resolve_path(explicit)
            if not _looks_like_project(folder, spec.package):
                folder = None  # ruta puesta a mano pero no parece el proyecto
        else:
            folder = autodetect_project(spec.package, search_root)
        result[spec.key] = ManagedProject(spec, folder)
    return result
