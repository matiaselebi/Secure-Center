"""Que algo arranque solo con la máquina, sin que el resto sepa cómo.

EL PROBLEMA

Hasta acá, "arrancar solo" era `schtasks`, escrito a mano en el orquestador.
En Windows funciona perfecto. En Linux ese comando no existe, así que
`_autostart_steps` devolvía lista vacía: SecureCenter arrancaba, decía que
todo estaba bien, y no dejaba nada configurado para el próximo arranque. Sin
un error, sin un aviso. Es exactamente la regla 10 al revés.

LA FORMA

La misma que ya usa SecureHIPS con el firewall: una interfaz chica y una
implementación por sistema. El orquestador pide "instalá el arranque de esto"
y no sabe si abajo hay una tarea programada o una unidad de systemd.

La interfaz es a propósito de cuatro métodos y nada más. Cuanto más chica,
más fácil es que la segunda implementación sea fiel a la primera.

LO QUE NO CAMBIA

**El camino de Windows tiene que quedar idéntico al que ya andaba.** No es una
buena intención: hay un test que fija el comando exacto de `schtasks`,
argumento por argumento. Si alguien lo "mejora" mientras trabaja en la parte
de Linux, ese test lo frena.

EL DETALLE DE LINUX QUE ARRUINA TODO SI NO SE SABE

Las unidades de usuario de systemd (`systemctl --user`) no necesitan root, que
es justo lo que queremos. Pero por defecto **solo corren mientras hay una
sesión abierta**: en un servidor headless, donde nadie inicia sesión nunca, un
`enable` sale bien y el servicio no arranca jamás. Lo que lo arregla es
`loginctl enable-linger`. Acá se detecta y se avisa, en vez de dejar a alguien
creyendo que configuró un arranque automático que no existe.
"""

import getpass
import os
import platform
import shutil
import subprocess
from pathlib import Path

from .procutil import run_quiet

# --------------------------------------------------------------------------
# Interfaz


class Arranque:
    """Instalar, quitar y consultar el arranque automático de algo.

    `instalar` recibe un argv ya armado (el intérprete y el script), no una
    línea de comando en texto. Es la misma razón de siempre: una línea de
    texto hay que citarla, y citar mal una ruta con espacios (`C:\\Program
    Files\\...`, `/home/mati/mis proyectos/...`) es la clase de bug que
    aparece solo en la máquina de otro.
    """

    sistema = "?"
    disponible = False

    def instalar(self, nombre: str, argv: list, cwd: str = "") -> tuple[bool, str]:
        raise NotImplementedError

    def quitar(self, nombre: str) -> tuple[bool, str]:
        raise NotImplementedError

    def esta_instalado(self, nombre: str) -> bool:
        raise NotImplementedError

    def avisos(self) -> list:
        """Cosas que hay que decirle al usuario sobre este sistema.

        Vacío no significa "todo bien", significa "no hay nada raro que
        contar". Los avisos existen para el caso de systemd sin linger, que
        es un arranque automático que se instala bien y no arranca nunca.
        """
        return []


# --------------------------------------------------------------------------
# Windows: tareas programadas


class ArranqueWindows(Arranque):
    """`schtasks`, exactamente como venía funcionando.

    `/sc onlogon` y no `/sc onstart` a propósito: la tarea corre como el
    usuario que inició sesión, no como SYSTEM. El panel escucha en 127.0.0.1
    y sus archivos viven en el perfil del usuario; corriendo como SYSTEM sería
    otro usuario, con otro perfil y otro escritorio.

    `/rl limited` y no `/rl highest` por lo mismo de siempre: lo que necesita
    permisos de administrador (el DNS del sistema, el firewall) se pide cuando
    hace falta, con un UAC que se ve. Una tarea elevada que arranca sola en
    cada login es una puerta abierta permanente para ahorrarse un clic.
    """

    sistema = "Windows"
    disponible = True

    def comando_instalar(self, nombre: str, argv: list) -> list:
        """El argv exacto de schtasks. Separado para poder fijarlo en un test."""
        objetivo = " ".join(f'"{parte}"' for parte in argv)
        return ["schtasks", "/create", "/tn", nombre, "/tr", objetivo,
                "/sc", "onlogon", "/rl", "limited", "/f"]

    def comando_quitar(self, nombre: str) -> list:
        return ["schtasks", "/delete", "/tn", nombre, "/f"]

    def instalar(self, nombre: str, argv: list, cwd: str = "") -> tuple[bool, str]:
        try:
            resultado = run_quiet(self.comando_instalar(nombre, argv), timeout=30)
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"no pude crear la tarea {nombre}: {exc}"
        if resultado.returncode == 0:
            return True, f"tarea programada {nombre} creada"
        salida = (resultado.stderr or resultado.stdout or "").strip()
        return False, f"schtasks falló para {nombre}: {salida[:150]}"

    def quitar(self, nombre: str) -> tuple[bool, str]:
        try:
            resultado = run_quiet(self.comando_quitar(nombre), timeout=30)
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"no pude borrar la tarea {nombre}: {exc}"
        # Que no exista NO es un error: quitar algo que ya no está es el
        # resultado que se pedía.
        if resultado.returncode == 0:
            return True, f"tarea {nombre} quitada"
        return True, f"la tarea {nombre} no estaba"

    def esta_instalado(self, nombre: str) -> bool:
        try:
            return run_quiet(["schtasks", "/query", "/tn", nombre],
                             timeout=20).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False


# --------------------------------------------------------------------------
# Linux: unidades de systemd


PLANTILLA = """\
# Generado por SecureCenter. NO editar a mano: se sobreescribe.
[Unit]
Description={descripcion}
After=network-online.target
Wants=network-online.target
# El tope de reintentos: si falla una y otra vez, systemd deja de intentar en
# vez de reiniciarlo para siempre. Un servicio mal configurado no puede
# comerse la máquina a fuerza de reinicios.
#
# VA EN [Unit] Y NO EN [Service]. Es un cambio de systemd 229 en adelante, y
# es de los peores errores posibles de copiar de un tutorial viejo: puesto en
# [Service], systemd lo IGNORA con un aviso que nadie lee y el tope no existe.
# Se verificó con `systemd-analyze verify`, que es lo que lo destapó.
StartLimitBurst=5
StartLimitIntervalSec=120

[Service]
Type=simple
ExecStart={ejecutar}
WorkingDirectory={carpeta}
Restart=on-failure
RestartSec=10

[Install]
WantedBy={objetivo}
"""


def _citar(texto: str) -> str:
    """Cita una ruta para `ExecStart`.

    systemd parte `ExecStart` por espacios, así que una ruta con espacios sin
    comillas se convierte en dos argumentos y el servicio no arranca. Las
    comillas dobles se escapan porque una ruta puede tenerlas en Linux.
    """
    return '"' + str(texto).replace("\\", "\\\\").replace('"', '\\"') + '"'


class ArranqueSystemd(Arranque):
    """Unidades de systemd. Por defecto de usuario, sin root.

    ALCANCE DE USUARIO (el de fábrica). La unidad va a
    `~/.config/systemd/user/` y se maneja con `systemctl --user`. No hace
    falta root, que en una máquina de escritorio es lo correcto: instalar un
    arranque automático no debería pedir la contraseña de administrador.

    ALCANCE DE SISTEMA. La unidad va a `/etc/systemd/system/` y arranca en el
    boot, sin que nadie inicie sesión. Necesita root. Es lo que va a querer el
    servidor de Debian.

    EL LINGER, QUE ES LA TRAMPA. Con alcance de usuario y sin
    `loginctl enable-linger`, la unidad se instala bien, `enable` devuelve
    cero, y el servicio no arranca nunca en una máquina donde nadie inicia
    sesión. Por eso `avisos()` lo revisa: es la diferencia entre un arranque
    automático y una ilusión de arranque automático.
    """

    sistema = "Linux"

    def __init__(self, alcance: str = "usuario", raiz=None, usuario: str = ""):
        self.alcance = "sistema" if alcance == "sistema" else "usuario"
        self.usuario = usuario or _usuario_actual()
        if raiz is not None:
            self.carpeta = Path(raiz)
        elif self.alcance == "sistema":
            self.carpeta = Path("/etc/systemd/system")
        else:
            self.carpeta = Path.home() / ".config" / "systemd" / "user"
        self.disponible = shutil.which("systemctl") is not None

    # ------------------------------------------------------------ interno

    def _flags(self) -> list:
        return [] if self.alcance == "sistema" else ["--user"]

    def _objetivo(self) -> str:
        # `default.target` para el usuario y `multi-user.target` para el
        # sistema. Poner multi-user en una unidad de usuario es un error que
        # systemd acepta y después no arranca nada.
        return "multi-user.target" if self.alcance == "sistema" else "default.target"

    def archivo(self, nombre: str) -> Path:
        return self.carpeta / f"{self.nombre_unidad(nombre)}"

    @staticmethod
    def nombre_unidad(nombre: str) -> str:
        """De `SecureCenterCoreAutostart` a `securecenter-core-autostart.service`.

        Se normaliza porque los nombres vienen pensados para Windows, donde el
        CamelCase con espacios es lo normal, y en systemd lo habitual es
        minúsculas con guiones. Además se filtra todo lo que no sea letra,
        número o guión: el nombre termina siendo un nombre de archivo y no
        puede traer una barra ni un `..`.
        """
        salida = []
        for i, letra in enumerate(nombre):
            if letra.isupper() and i > 0 and not nombre[i - 1].isupper():
                salida.append("-")
            salida.append(letra.lower() if letra.isalnum() else "-")
        limpio = "".join(salida).strip("-")
        while "--" in limpio:
            limpio = limpio.replace("--", "-")
        return f"{limpio or 'securesuite'}.service"

    def _systemctl(self, *args) -> tuple[bool, str]:
        try:
            resultado = run_quiet(["systemctl", *self._flags(), *args], timeout=30)
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"no pude correr systemctl: {exc}"
        if resultado.returncode == 0:
            return True, ""
        return False, (resultado.stderr or resultado.stdout or "").strip()[:200]

    # ------------------------------------------------------------ interfaz

    def contenido(self, nombre: str, argv: list, cwd: str = "") -> str:
        return PLANTILLA.format(
            descripcion=f"SecureSuite: {nombre}",
            ejecutar=" ".join(_citar(parte) for parte in argv),
            carpeta=cwd or str(Path(argv[-1]).resolve().parent if argv else "/"),
            objetivo=self._objetivo(),
        )

    def instalar(self, nombre: str, argv: list, cwd: str = "") -> tuple[bool, str]:
        if not self.disponible:
            return False, "no hay systemctl en esta máquina"
        if not argv:
            return False, "no hay nada que ejecutar"
        unidad = self.archivo(nombre)
        try:
            unidad.parent.mkdir(parents=True, exist_ok=True)
            unidad.write_text(self.contenido(nombre, argv, cwd), encoding="utf-8")
        except OSError as exc:
            extra = (" (el alcance 'sistema' escribe en /etc y necesita root)"
                     if self.alcance == "sistema" else "")
            return False, f"no pude escribir {unidad}: {exc}{extra}"

        ok, error = self._systemctl("daemon-reload")
        if not ok:
            return False, f"daemon-reload falló: {error}"
        ok, error = self._systemctl("enable", "--now", unidad.name)
        if not ok:
            return False, f"no pude habilitar {unidad.name}: {error}"
        return True, f"unidad {unidad.name} instalada y habilitada"

    def quitar(self, nombre: str) -> tuple[bool, str]:
        if not self.disponible:
            return False, "no hay systemctl en esta máquina"
        unidad = self.archivo(nombre)
        # `disable --now` primero: borrar el archivo con la unidad todavía
        # habilitada deja un enlace roto en `.wants/` y systemd se queja en
        # cada arranque de algo que ya no existe.
        self._systemctl("disable", "--now", unidad.name)
        try:
            if unidad.exists():
                unidad.unlink()
        except OSError as exc:
            return False, f"no pude borrar {unidad}: {exc}"
        self._systemctl("daemon-reload")
        return True, f"unidad {unidad.name} quitada"

    def esta_instalado(self, nombre: str) -> bool:
        return self.archivo(nombre).exists()

    def avisos(self) -> list:
        """El aviso del linger, que es el que evita la ilusión de arranque."""
        avisos = []
        if not self.disponible:
            avisos.append("no encontré systemctl: no puedo dejar nada arrancando solo")
            return avisos
        if self.alcance == "usuario" and not _tiene_linger(self.usuario):
            avisos.append(
                "las unidades de usuario solo corren mientras hay una sesión "
                f"abierta. En un servidor sin pantalla NO van a arrancar. "
                f"Arreglalo con:  sudo loginctl enable-linger {self.usuario}  "
                "(o usá arranque.alcance: \"sistema\" en el config)")
        return avisos


def _usuario_actual() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return os.environ.get("USER") or "tu-usuario"


def _tiene_linger(usuario: str) -> bool:
    """¿Este usuario tiene linger activado?

    Se pregunta a `loginctl`. Si no está o falla, se contesta que NO: es mejor
    mostrar un aviso de más que dejar a alguien creyendo que su servidor
    headless va a levantar la suite sola.
    """
    if shutil.which("loginctl") is None:
        return False
    try:
        resultado = run_quiet(["loginctl", "show-user", usuario,
                               "--property=Linger"], timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return resultado.returncode == 0 and "Linger=yes" in (resultado.stdout or "")


# --------------------------------------------------------------------------
# Sistema desconocido


class ArranqueNoDisponible(Arranque):
    """Ni Windows ni systemd. Contesta que no, y dice por qué.

    Existe para no volver al bug de origen: devolver lista vacía y que el
    panel muestre todo en verde. Un macOS, un Linux con OpenRC o un contenedor
    sin init tienen que dar un mensaje, no un silencio.
    """

    disponible = False

    def __init__(self, motivo: str = ""):
        self.sistema = platform.system() or "desconocido"
        self.motivo = motivo or (
            f"no sé dejar cosas arrancando solas en {self.sistema}. "
            "Los servicios se encienden a mano (o armá vos el arranque de tu sistema)")

    def instalar(self, nombre: str, argv: list, cwd: str = "") -> tuple[bool, str]:
        return False, self.motivo

    def quitar(self, nombre: str) -> tuple[bool, str]:
        # Quitar algo que nunca se pudo instalar es un éxito trivial: no hay
        # nada. Devolver un error acá haría fallar el apagado por una función
        # que ni existe en este sistema.
        return True, "no hay arranque automático que quitar en este sistema"

    def esta_instalado(self, nombre: str) -> bool:
        return False

    def avisos(self) -> list:
        return [self.motivo]


# --------------------------------------------------------------------------
# Elección


def elegir(cfg=None, sistema: str = "") -> Arranque:
    """El backend que corresponde a esta máquina.

    Se pasa `sistema` explícito solo en los tests: así se puede probar el
    comando de Windows sin estar en Windows, que es la única forma de que ese
    camino siga cubierto cuando el CI corre en Ubuntu.
    """
    sistema = sistema or platform.system()
    if sistema == "Windows":
        return ArranqueWindows()
    if sistema == "Linux":
        alcance = "usuario"
        conf = getattr(cfg, "arranque", None)
        if conf is not None:
            alcance = getattr(conf, "alcance", "usuario")
        backend = ArranqueSystemd(alcance)
        if not backend.disponible:
            return ArranqueNoDisponible(
                "este Linux no usa systemd: no puedo dejar nada arrancando solo")
        return backend
    return ArranqueNoDisponible()
