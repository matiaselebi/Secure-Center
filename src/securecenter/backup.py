"""Copia de seguridad de la configuración de toda la suite.

QUÉ SE GUARDA, Y POR QUÉ NO TODO

Se guarda lo que **no se puede volver a generar**: los `config.yaml` de los
proyectos disponibles, tus listas manuales (la blanca y la negra de cada uno) y las
preferencias del panel. Eso es lo que tardaste en armar.

No se guardan las bases de datos, salvo que lo pidas. Son lo más pesado del
proyecto y lo más reemplazable: el historial de bloqueos es útil, pero si se
pierde, la herramienta sigue protegiendo igual desde el minuto cero. Un backup
que tarda cinco minutos y ocupa dos giga es un backup que nadie hace.

LO QUE NUNCA ENTRA: EL .ENV

Los `.env` quedan afuera **siempre**, sin opción para incluirlos. Ahí viven el
token de Telegram, la clave de AbuseIPDB y el token de la API del HIPS. Un
backup con secretos adentro es un archivo que termina en Descargas, en un
pendrive o adjunto en un mail, y del que nadie se acuerda. Restaurar en una
máquina nueva pide volver a poner esos cuatro valores a mano, y está bien que
así sea.

RESTAURAR PISA COSAS, ASÍ QUE PRIMERO GUARDA

Antes de escribir nada, `restaurar()` hace una copia de lo que está por pisar.
Si el zip venía mal o te arrepentís, ese archivo es la vuelta atrás. Restaurar
sin red de contención es la clase de función que se usa una vez y arruina una
tarde.
"""

import os
import shutil
import stat
import tempfile
import time
import zipfile
from datetime import datetime
from pathlib import Path, PurePosixPath

# Qué se lleva de cada proyecto. Son patrones relativos a su carpeta.
QUE_SE_GUARDA = ("config/*.yaml", "config/*.yml", "data/*.txt")

# Lo mismo pero pesado, y por eso opcional.
HISTORIAL = ("data/*.db",)

# Lo que NUNCA se guarda, pase lo que pase. Se chequea por nombre de archivo,
# así que da igual en qué carpeta esté.
PROHIBIDOS = (".env", ".env.local", "credentials.json", "id_rsa")

MAXIMO_POR_ARCHIVO = 200 * 1024 * 1024  # 200 MB
MAXIMO_TOTAL_RESTAURACION = 1024 * 1024 * 1024  # 1 GiB descomprimido
MAXIMO_ARCHIVOS_RESTAURACION = 1000


def _prohibido(ruta: Path) -> bool:
    return ruta.name in PROHIBIDOS or ruta.name.startswith(".env")


def _archivos_de(carpeta: Path, patrones) -> list[Path]:
    """Archivos reales dentro del proyecto, nunca symlinks hacia afuera."""
    encontrados = []
    raiz = carpeta.resolve()
    for patron in patrones:
        for ruta in sorted(carpeta.glob(patron)):
            if ruta.is_symlink() or not ruta.is_file() or _prohibido(ruta):
                continue
            try:
                real = ruta.resolve(strict=True)
            except OSError:
                continue
            if not real.is_relative_to(raiz):
                continue
            encontrados.append(ruta)
    return encontrados


def _relativo_permitido(relativo: str) -> bool:
    """Solo restaura las mismas clases de archivo que SecureCenter respalda.

    Un zip puesto a mano en la carpeta de backups no puede aprovechar el
    botón Restaurar para reemplazar código Python u otros archivos del repo.
    """
    limpio = relativo.replace("\\", "/")
    ruta = PurePosixPath(limpio)
    if ruta.is_absolute() or len(ruta.parts) != 2:
        return False
    carpeta, nombre = ruta.parts
    if any(p in ("", ".", "..") for p in ruta.parts):
        return False
    if Path(nombre).name in PROHIBIDOS or Path(nombre).name.startswith(".env"):
        return False
    sufijo = PurePosixPath(nombre).suffix.lower()
    return (
        carpeta == "config" and sufijo in {".yaml", ".yml"}
    ) or (
        carpeta == "data" and sufijo in {".txt", ".db"}
    )


def crear(projects: dict, destino: Path, incluir_historial: bool = False,
          ahora: float | None = None) -> dict:
    """Arma el zip. Devuelve un resumen de qué entró y qué no."""
    ahora = time.time() if ahora is None else ahora
    destino = Path(destino)
    destino.parent.mkdir(parents=True, exist_ok=True)
    patrones = QUE_SE_GUARDA + (HISTORIAL if incluir_historial else ())

    guardados, salteados = [], []
    with zipfile.ZipFile(destino, "w", zipfile.ZIP_DEFLATED) as zf:
        for clave, project in sorted(projects.items()):
            if project is None or not project.found:
                continue
            for ruta in _archivos_de(project.folder, patrones):
                try:
                    tamano = ruta.stat().st_size
                except OSError:
                    salteados.append(f"{clave}/{ruta.name} (no se pudo leer)")
                    continue
                if tamano > MAXIMO_POR_ARCHIVO:
                    salteados.append(f"{clave}/{ruta.name} (más de 200 MB)")
                    continue
                relativo = ruta.relative_to(project.folder)
                # El nombre adentro del zip lleva la CLAVE del proyecto y no
                # el nombre de la carpeta: así se restaura entre máquinas.
                zf.write(ruta, f"{clave}/{relativo.as_posix()}")
                guardados.append(f"{clave}/{relativo.as_posix()}")
        zf.writestr("backup.txt", (
            "Copia de configuración de la suite Secure*, hecha por SecureCenter.\n"
            f"Fecha: {datetime.fromtimestamp(ahora).strftime('%d/%m/%Y %H:%M:%S')}\n"
            f"Archivos: {len(guardados)}\n"
            f"Historial de las bases: {'sí' if incluir_historial else 'no'}\n"
            "\n"
            "Los archivos .env NO están acá, a propósito: contienen el token de\n"
            "Telegram, la clave de AbuseIPDB y el token de la API de SecureHIPS.\n"
            "Al restaurar en una máquina nueva hay que volver a ponerlos a mano.\n"
        ))
    return {"archivo": str(destino), "guardados": guardados,
            "salteados": salteados, "total": len(guardados)}


def contenido(archivo: Path) -> list[str]:
    """Qué trae un zip, sin tocar nada. Para poder mirarlo antes de aplicarlo."""
    try:
        with zipfile.ZipFile(archivo) as zf:
            return [n for n in zf.namelist() if n != "backup.txt"]
    except (zipfile.BadZipFile, OSError):
        return []


def _plan_de_restauracion(projects: dict, zf: zipfile.ZipFile) -> tuple[list, list[str]]:
    """Valida el zip entero antes de escribir el primer byte."""
    plan = []
    ignorados: list[str] = []
    total = 0
    cantidad = 0

    for info in zf.infolist():
        nombre_original = info.filename
        if nombre_original == "backup.txt" or info.is_dir():
            continue
        cantidad += 1
        if cantidad > MAXIMO_ARCHIVOS_RESTAURACION:
            raise ValueError(
                f"el zip trae más de {MAXIMO_ARCHIVOS_RESTAURACION} archivos")
        if info.file_size > MAXIMO_POR_ARCHIVO:
            raise ValueError(
                f"{nombre_original} supera el máximo de 200 MB descomprimido")
        total += info.file_size
        if total > MAXIMO_TOTAL_RESTAURACION:
            raise ValueError("el zip supera 1 GiB descomprimido")

        # Un zip puede describir symlinks en Unix. No los materializamos ni
        # los seguimos: un backup de configuración no necesita enlaces.
        modo = (info.external_attr >> 16) & 0xFFFF
        if modo and stat.S_ISLNK(modo):
            ignorados.append(f"{nombre_original} (enlace simbólico no permitido)")
            continue

        normalizado = nombre_original.replace("\\", "/")
        partes = normalizado.split("/", 1)
        if len(partes) != 2:
            ignorados.append(nombre_original)
            continue
        clave, relativo = partes
        if ".." in PurePosixPath(relativo).parts:
            ignorados.append(f"{nombre_original} (intentaba salirse de la carpeta)")
            continue
        if not _relativo_permitido(relativo):
            ignorados.append(f"{nombre_original} (tipo o ruta no respaldable)")
            continue
        project = projects.get(clave)
        if project is None or not project.found:
            ignorados.append(f"{nombre_original} (ese proyecto no está acá)")
            continue

        raiz = project.folder.resolve()
        destino = (project.folder / Path(*PurePosixPath(relativo).parts)).resolve()
        if not destino.is_relative_to(raiz):
            ignorados.append(f"{nombre_original} (intentaba salirse de la carpeta)")
            continue
        if _prohibido(destino):
            ignorados.append(f"{nombre_original} (no se restauran secretos)")
            continue
        plan.append((info, destino, nombre_original))
    return plan, ignorados


def _escribir_atomico(zf: zipfile.ZipFile, info: zipfile.ZipInfo, destino: Path) -> None:
    """Copia un miembro sin cargarlo entero en RAM y lo publica con replace."""
    destino.parent.mkdir(parents=True, exist_ok=True)
    fd, temporal = tempfile.mkstemp(prefix=f".{destino.name}.", suffix=".tmp",
                                    dir=str(destino.parent))
    try:
        with os.fdopen(fd, "wb") as salida, zf.open(info, "r") as entrada:
            shutil.copyfileobj(entrada, salida, length=1024 * 1024)
            salida.flush()
            os.fsync(salida.fileno())
        os.replace(temporal, destino)
    except Exception:
        try:
            os.unlink(temporal)
        except OSError:
            pass
        raise


def restaurar(projects: dict, archivo: Path, ahora: float | None = None) -> dict:
    """Vuelca el zip sobre los proyectos, después de guardar lo que va a pisar.

    Devuelve `{"ok": bool, "detalle": str, "respaldo": ruta}`. Nunca lanza:
    esto se llama desde un botón, y una excepción acá deja la configuración a
    mitad de camino sin que nadie sepa en qué estado quedó.
    """
    ahora = time.time() if ahora is None else ahora
    archivo = Path(archivo)
    if not archivo.exists() or not archivo.is_file():
        return {"ok": False, "detalle": f"no encontré {archivo}", "respaldo": ""}

    try:
        zf = zipfile.ZipFile(archivo)
        plan, ignorados = _plan_de_restauracion(projects, zf)
    except (zipfile.BadZipFile, OSError, RuntimeError, ValueError) as exc:
        try:
            zf.close()  # type: ignore[possibly-undefined]
        except (NameError, OSError):
            pass
        return {"ok": False, "detalle": f"el archivo no es un zip válido o backup aceptable ({exc})",
                "respaldo": ""}

    if not plan:
        zf.close()
        detalle = "el backup no trae ningún archivo restaurable"
        if ignorados:
            detalle += f"; ignoré {len(ignorados)}: {', '.join(ignorados[:5])}"
        return {"ok": False, "detalle": detalle, "respaldo": ""}

    # Antes de pisar nada: la vuelta atrás.
    marca = datetime.fromtimestamp(ahora).strftime("%Y%m%d-%H%M%S")
    respaldo = archivo.parent / f"antes-de-restaurar-{marca}.zip"
    try:
        # Si vamos a pisar una base, la red de contención tiene que guardar
        # también las bases actuales; de lo contrario el rollback prometido
        # por la función estaría incompleto justo en la restauración pesada.
        incluye_historial = any(destino.suffix.lower() == ".db"
                                for _info, destino, _nombre in plan)
        crear(projects, respaldo, incluir_historial=incluye_historial, ahora=ahora)
    except OSError as exc:
        zf.close()
        return {"ok": False, "respaldo": "",
                "detalle": f"no pude guardar el estado actual, así que no "
                           f"restauro nada ({exc})"}

    escritos = []
    try:
        with zf:
            for info, destino, nombre in plan:
                _escribir_atomico(zf, info, destino)
                escritos.append(nombre)
    except (zipfile.BadZipFile, OSError, RuntimeError, ValueError) as exc:
        return {"ok": False, "respaldo": str(respaldo),
                "detalle": f"falló a mitad de camino ({exc}). El estado "
                           f"anterior quedó en {respaldo.name}"}

    detalle = f"restauré {len(escritos)} archivo(s)"
    if ignorados:
        detalle += f"; ignoré {len(ignorados)}: {', '.join(ignorados[:5])}"
    detalle += (f". Antes de tocar nada guardé lo que había en "
                f"{respaldo.name}. Reiniciá los servicios para que tomen la "
                f"configuración nueva.")
    return {"ok": bool(escritos), "detalle": detalle, "respaldo": str(respaldo)}
