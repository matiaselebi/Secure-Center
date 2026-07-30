"""Utilidades de procesos y puertos, SIN ventanas y sin PowerShell.

Por qué existe este módulo:

1. **Sin ventanas.** En Windows, cada `subprocess` de un programa de consola
   (python.exe, reg.exe, taskkill, powershell) abre una ventana que
   "parpadea". El dashboard corre estas cosas seguido, así que todo acá usa
   CREATE_NO_WINDOW.
2. **Rápido.** Arrancar PowerShell cuesta cerca de un segundo. `netstat` y
   `taskkill` arrancan en milisegundos, así que matar por puerto se hace con
   esos dos en vez de con Get-NetTCPConnection/Stop-Process.
3. **Honesto.** La versión anterior usaba `-ErrorAction SilentlyContinue`:
   si el kill fallaba (por ejemplo por falta de permisos), igual informaba
   "OK" y el servicio seguía prendido. Acá cada función devuelve qué pasó de
   verdad, y `free_port` VERIFICA que el puerto haya quedado libre.
"""

import ctypes
import platform
import subprocess
import threading
import time

# Windows: ejecutar sin abrir ventana de consola. En Linux/macOS es 0.
NO_WINDOW = 0x08000000 if platform.system() == "Windows" else 0


def is_windows() -> bool:
    return platform.system() == "Windows"


def run_quiet(argv, cwd=None, timeout=60, stdin_text=None) -> subprocess.CompletedProcess:
    """subprocess.run sin ventana, capturando salida."""
    return subprocess.run(
        argv,
        cwd=cwd,
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=NO_WINDOW,
    )


def run_streaming(argv, cwd=None, timeout=60, on_line=None) -> int:
    """Como run_quiet, pero entrega cada línea de salida APENAS aparece.

    Es lo que permite ver la consola en vivo en el dashboard en vez de un
    silencio de varios minutos seguido de todo el texto junto. Encender la
    VPN, por ejemplo, tarda porque arranca Docker, construye el laboratorio
    y aprovisiona por SSH: cada una de esas etapas se imprime a medida que
    pasa, y acá se reenvía al panel en el momento.

    Devuelve el código de salida. Levanta `subprocess.TimeoutExpired` si el
    proceso se pasa del tiempo (y lo mata antes de salir).

    La lectura va en un hilo aparte a propósito: `readline()` bloquea, así
    que si el proceso se cuelga sin escribir nada, esperarlo desde el hilo
    principal es la única forma de que el timeout se respete de verdad.
    """
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,  # una sola corriente: es "la consola"
        text=True,
        bufsize=1,  # línea por línea
        creationflags=NO_WINDOW,
    )

    def leer():
        try:
            for linea in proc.stdout:  # type: ignore[union-attr]
                texto = linea.rstrip()
                if texto and on_line is not None:
                    on_line(texto)
        except (OSError, ValueError):
            pass

    lector = threading.Thread(target=leer, daemon=True)
    lector.start()
    try:
        codigo = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)
        raise
    finally:
        lector.join(timeout=5)
        if proc.stdout is not None:
            try:
                proc.stdout.close()
            except OSError:
                pass
    return codigo


def popen_quiet(argv, cwd=None) -> subprocess.Popen:
    """Lanza un proceso que queda corriendo, sin ventana ni salida colgando."""
    return subprocess.Popen(
        argv,
        cwd=cwd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=NO_WINDOW,
    )


def is_admin() -> bool:
    """¿El proceso actual tiene permisos de administrador?

    Importa porque matar un proceso que arrancó elevado requiere estar
    elevado: si el dashboard se abrió sin admin, los botones de apagar
    fallan y hay que decírselo al usuario en vez de fingir que anduvo."""
    if not is_windows():
        try:
            import os

            return os.geteuid() == 0
        except AttributeError:
            return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - si no se puede saber, asumimos que no
        return False


def run_elevated(argv: list[str], espera_maxima: float = 30.0) -> tuple[bool, str]:
    """Ejecuta un comando PIDIENDO permisos de administrador (UAC).

    Por qué hace falta: el núcleo se enciende desde SecureCenter.bat, que se
    auto-eleva, así que SecureProxy y SecureDNS quedan corriendo como
    administrador. Pero el dashboard arranca con Windows mediante una tarea
    de inicio de sesión, que NO es elevada. Resultado: los botones de apagar
    fallaban con "acceso denegado" y había que cerrar el navegador e ir al
    .bat para apagar algo que se prendió desde el navegador.

    Con esto, cuando un kill falla por permisos, el dashboard levanta UNA
    sola ventana de UAC y hace el trabajo. Si el usuario cancela, se informa
    exactamente eso, sin fingir que salió bien.

    `ShellExecuteW` no espera a que el proceso termine, así que después de
    lanzarlo hay que verificar el efecto (que es justo lo que hace
    `free_port` al esperar a que el puerto quede libre).
    """
    if not is_windows():
        return False, "elevación solo aplica a Windows"
    try:
        SW_HIDE = 0
        parametros = subprocess.list2cmdline(argv[1:])
        resultado = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", argv[0], parametros, None, SW_HIDE
        )
    except Exception as exc:  # noqa: BLE001
        return False, f"no se pudo pedir permisos de administrador: {exc}"

    # ShellExecuteW devuelve un valor > 32 si pudo lanzar el proceso.
    # El 5 (ERROR_ACCESS_DENIED) es el caso típico: el usuario le dio "No"
    # al cartel de UAC.
    if resultado == 5:
        return False, "cancelaste el pedido de permisos de administrador"
    if resultado <= 32:
        return False, f"no se pudo elevar (código {resultado})"
    return True, "ejecutado con permisos de administrador"


def parse_netstat_listening(output: str, port: int) -> set[int]:
    """Extrae los PIDs que ESCUCHAN en ese puerto, de la salida de
    `netstat -ano`. Se filtra por el puerto exacto del extremo local (no
    alcanza con buscar el número suelto: aparecería también como puerto
    remoto o dentro de otra dirección)."""
    pids: set[int] = set()
    for line in output.splitlines():
        parts = line.split()
        # Formato: Proto  DirecciónLocal  DirecciónRemota  Estado  PID
        if len(parts) < 5 or not parts[0].upper().startswith("TCP"):
            continue
        if "LISTEN" not in parts[3].upper():
            continue
        local = parts[1]
        if ":" not in local:
            continue
        local_port = local.rsplit(":", 1)[1]
        if local_port != str(port):
            continue
        try:
            pid = int(parts[4])
        except ValueError:
            continue
        if pid > 0:
            pids.add(pid)
    return pids


def parse_ss_listening(output: str, port: int) -> set[int]:
    """Igual que la anterior pero para el formato de Linux (`ss -ltnp`), que
    trae el PID como `users:(("proc",pid=1234,fd=3))`. Existe para que el
    módulo (y su test contra un proceso real) funcione también en Linux, que
    es donde corre el CI."""
    import re

    pids: set[int] = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        # La dirección local es la penúltima antes de la remota; se busca el
        # campo que termine en ":<puerto>".
        local = next(
            (p for p in parts if p.rsplit(":", 1)[-1] == str(port) and ":" in p), None
        )
        if local is None:
            continue
        for match in re.finditer(r"pid=(\d+)", line):
            pids.add(int(match.group(1)))
    return pids


def listening_pids(port: int) -> set[int]:
    """PIDs que están escuchando en ese puerto local, ahora mismo."""
    if is_windows():
        try:
            result = run_quiet(["netstat", "-ano"], timeout=20)
        except (OSError, subprocess.SubprocessError):
            return set()
        return parse_netstat_listening(result.stdout, port)

    # Linux/macOS: `ss` es lo estándar hoy; si no está, se cae a netstat.
    for argv, parser in (
        (["ss", "-ltnp"], parse_ss_listening),
        (["netstat", "-ltnp"], parse_ss_listening),
    ):
        try:
            result = run_quiet(argv, timeout=20)
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode == 0:
            found = parser(result.stdout, port)
            if found:
                return found
    return set()


def port_in_use(port: int) -> bool:
    return bool(listening_pids(port))


def kill_pid(pid: int) -> tuple[bool, str]:
    """Mata un proceso y su árbol (/T), a la fuerza (/F). Devuelve (ok, detalle
    real): si falla por permisos, lo dice en vez de tragárselo."""
    if not is_windows():
        import os
        import signal

        try:
            os.kill(pid, signal.SIGKILL)
            return True, f"proceso {pid} terminado"
        except ProcessLookupError:
            return True, f"el proceso {pid} ya no existía"
        except PermissionError:
            return False, f"sin permisos para matar el proceso {pid}"
        except OSError as exc:
            return False, f"no se pudo matar {pid}: {exc}"

    try:
        result = run_quiet(["taskkill", "/PID", str(pid), "/F", "/T"], timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"no se pudo ejecutar taskkill: {exc}"
    if result.returncode == 0:
        return True, f"proceso {pid} terminado"
    salida = (result.stderr or result.stdout or "").strip()
    bajo = salida.lower()
    # taskkill /T se queja cuando un proceso HIJO ya había terminado solo
    # ("no hay ninguna instancia activa de la tarea"). No es un error: el
    # objetivo -que el proceso muera- se cumplió igual. Antes esto se
    # mostraba como una advertencia larga y alarmante aunque todo hubiera
    # salido bien.
    ya_no_estaba = (
        "not found" in bajo
        or "no se encontr" in bajo
        or "no running instance" in bajo
        or "ninguna instancia activa" in bajo
    )
    if ya_no_estaba:
        return True, f"proceso {pid} terminado (algún hijo ya se había cerrado solo)"
    if "denied" in salida.lower() or "denegado" in salida.lower():
        return False, (
            f"acceso denegado al matar el proceso {pid}: hace falta abrir "
            "SecureCenter como administrador"
        )
    return False, f"taskkill falló para {pid}: {salida[:150]}"


def free_port(port: int, timeout: float = 6.0) -> tuple[bool, str]:
    """Libera un puerto: mata a quien lo escuche y ESPERA a confirmar que
    quedó libre (Windows tarda un instante en soltarlo). Devuelve (ok,
    detalle) contando lo que realmente pasó."""
    pids = listening_pids(port)
    if not pids:
        return True, f"puerto {port}: ya estaba libre"

    detalles = []
    todo_ok = True
    denegados = []
    for pid in sorted(pids):
        ok, detalle = kill_pid(pid)
        detalles.append(detalle)
        todo_ok = todo_ok and ok
        if not ok and "denegado" in detalle:
            denegados.append(pid)

    # Si faltaron permisos, en vez de rendirse se pide UAC UNA sola vez para
    # todos los procesos que quedaron. Es lo que convierte "andá a abrirlo
    # como administrador y probá de nuevo" en "aceptá este cartel".
    if denegados and is_windows() and not is_admin():
        argv = ["taskkill.exe"]
        for pid in denegados:
            argv += ["/PID", str(pid)]
        argv += ["/F", "/T"]
        ok_elevado, detalle_elevado = run_elevated(argv)
        detalles.append(f"con permisos de administrador: {detalle_elevado}")
        if ok_elevado:
            todo_ok = True

    # Verificación real: esperar hasta que el puerto deje de estar escuchado.
    fin = time.time() + timeout
    while time.time() < fin:
        if not listening_pids(port):
            return True, f"puerto {port} liberado ({'; '.join(detalles)})"
        time.sleep(0.25)

    restantes = listening_pids(port)
    motivo = "; ".join(detalles) if detalles else "sin detalle"
    if not todo_ok:
        return False, f"puerto {port} SIGUE ocupado por {sorted(restantes)}. {motivo}"
    return False, (
        f"puerto {port} sigue ocupado por {sorted(restantes)} tras {timeout:.0f}s "
        f"({motivo}); puede estar reiniciándose solo (¿tarea de inicio automático?)"
    )


def windows_service_running(service_name: str) -> bool:
    """¿Existe y está corriendo ese servicio de Windows?

    Se usa para saber si el túnel de WireGuard quedó instalado: la app
    oficial crea un servicio llamado `WireGuardTunnel$<interfaz>`, que
    sobrevive reinicios. Si está corriendo, la VPN quedó encendida y
    corresponde levantar también su dashboard al iniciar sesión."""
    if not is_windows():
        return False
    try:
        result = run_quiet(["sc", "query", service_name], timeout=15)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and "RUNNING" in result.stdout.upper()


def wait_port_listening(port: int, timeout: float = 8.0) -> bool:
    """Espera a que algo empiece a escuchar en el puerto (para confirmar que
    un servicio arrancó de verdad). Devuelve apenas aparece."""
    fin = time.time() + timeout
    while True:
        if port_in_use(port):
            return True
        if time.time() >= fin:
            return False
        time.sleep(0.25)
