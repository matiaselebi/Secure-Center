"""Modelo de cada proyecto administrado y su autodetección.

Cada proyecto (SecureProxy, SecureDNS, SecureVPN, SecureHIPS,
Secure-Intel) se describe con lo mínimo
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
    key: str  # "proxy" | "dns" | "vpn" | "hips" | "intel"
    display_name: str
    package: str  # paquete en src/ que lo identifica (marcador de autodetección)
    role: str  # descripción corta para el dashboard
    # Ruta del dashboard de ese proyecto (¡no todos usan "/"!).
    #
    # None = ESE PROYECTO NO TIENE PANEL. No es lo mismo que "/": el panel de
    # SecureCenter ofrecía un link a los 8896 de Secure-Agent, que no existe.
    # Abrirlo da un 405, porque ese puerto solo acepta POST /ingesta.
    dashboard_path: str | None


PROJECT_SPECS: tuple[ProjectSpec, ...] = (
    # Todos sirven su panel en la raíz de su puerto de dashboard.
    ProjectSpec("proxy", "SecureProxy", "secureproxy", "filtro de conexiones", "/"),
    ProjectSpec("dns", "SecureDNS", "securedns", "filtro de nombres", "/"),
    ProjectSpec("vpn", "SecureVPN", "securevpn", "transporte cifrado", "/"),
    # SecureHIPS es el único que mira hacia ADENTRO: los otros filtran lo que
    # sale de la máquina, este ve a quien prueba contraseñas contra ella.
    ProjectSpec("hips", "SecureHIPS", "securehips", "lo que intenta entrar", "/"),
    # Secure-Intel no filtra ni bloquea: baja los feeds que usan los otros
    # tres. Que esté apagado NO deja a nadie sin protección, porque los datos
    # ya bajados se leen igual. Lo que se pierde es que se pongan al día.
    ProjectSpec("intel", "Secure-Intel", "secureintel", "de dónde salen los feeds", "/"),
    # Secure-Scanner tampoco filtra ni bloquea: mira qué hay conectado en la
    # red y desde cuándo. Es la única fuente que ve equipos que NO hablan con
    # esta máquina, así que aporta lo que ninguna otra puede.
    ProjectSpec("scanner", "Secure-Scanner", "securescanner", "qué hay en la red", "/"),
    # Secure-Agent es el único que ve DESDE ADENTRO de cada equipo. Lo que
    # SecureCenter administra es su SERVIDOR (el que recibe), que corre en
    # esta misma máquina; los agentes viven en las otras y se administran
    # solos. Ver el ADR 0001 de ese repositorio: el servidor nunca les pide
    # nada, así que tampoco podría arrancarlos.
    #
    # Y NO tiene panel propio: su puerto solo recibe POST en /ingesta y a
    # cualquier otra cosa contesta 405. Lo que se ve de los agentes se ve en
    # la pestaña Agentes y en la línea de tiempo de SecureCenter, que leen su
    # base. Por eso va None y no "/": ofrecer un link que da 405 es peor que
    # no ofrecer ninguno.
    ProjectSpec("agente", "Secure-Agent", "secureagent", "servidor que recibe telemetría", None),
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
        """Intérprete del venv del proyecto, o None si ese venv no existe.

        Antes esto devolvía la ruta SIEMPRE, existiera o no. Cuando alguien
        clonaba un proyecto nuevo y todavía no le había creado el venv,
        SecureCenter armaba igual el comando y `subprocess` fallaba con
        «[WinError 2] El sistema no puede encontrar el archivo especificado»,
        que no dice qué archivo ni qué hacer. Devolver None deja que el
        orquestador arme un paso con un mensaje que sí se entiende.

        En Windows además hay un caso real: `pythonw.exe` (el que arranca sin
        ventana) no viene en todos los venv. Si falta, se usa `python.exe`,
        porque una ventana de consola de más es mucho mejor que no arrancar.
        """
        if self.folder is None:
            return None
        if platform.system() == "Windows":
            carpeta = self.folder / "venv" / "Scripts"
            if windowless:
                sin_ventana = carpeta / "pythonw.exe"
                if sin_ventana.exists():
                    return sin_ventana
            normal = carpeta / "python.exe"
            return normal if normal.exists() else None
        interprete = self.folder / "venv" / "bin" / "python"
        return interprete if interprete.exists() else None

    def falta_el_venv(self) -> bool:
        """¿Está la carpeta pero sin entorno virtual creado?"""
        return self.found and self.venv_python() is None

    def script(self, relative: str) -> Path | None:
        return None if self.folder is None else self.folder / relative

    def db_path(self, relative: str) -> Path | None:
        return None if self.folder is None else self.folder / relative


def discover_projects(cfg: Config, search_root: Path | None = None) -> dict[str, ManagedProject]:
    """Arma el mapa key -> ManagedProject, usando primero la ruta explícita
    del config.yaml y, si está vacía, autodetectando entre las hermanas.

    search_root por defecto es la carpeta que contiene a SecureCenter (ahí
    viven los proyectos administrados, cada uno en su carpeta, según tu setup)."""
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
