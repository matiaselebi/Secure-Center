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
import socket
import subprocess
import threading
import time
from pathlib import Path

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


def popen_quiet(argv, cwd=None, log=None) -> subprocess.Popen:
    """Lanza un proceso que queda corriendo, sin ventana.

    `log` es la ruta donde se guarda lo que imprime, y no es un lujo: sin eso,
    un servicio que arranca, escribe el motivo por el que no puede seguir y se
    muere, deja EXACTAMENTE el mismo rastro que uno que arrancó bien. La salida
    iba a DEVNULL, así que el único camino era "corré su run_*.py a mano en una
    consola", que es pedirle a la persona que haga de depurador.

    Se abre en modo "w" y no "a": interesa el ÚLTIMO intento. Un archivo que
    crece con los veinte arranques anteriores obliga a buscar cuál es el de
    ahora, y ahí ya perdiste.
    """
    salida = subprocess.DEVNULL
    archivo = None
    if log:
        try:
            Path(log).parent.mkdir(parents=True, exist_ok=True)
            archivo = open(log, "w", encoding="utf-8", errors="replace")  # noqa: SIM115
            salida = archivo
        except OSError:
            # No poder escribir el log no puede impedir que el servicio
            # arranque: se pierde el diagnóstico, no el servicio.
            salida = subprocess.DEVNULL
    try:
        return subprocess.Popen(
            argv,
            cwd=cwd,
            stdout=salida,
            stderr=subprocess.STDOUT if archivo is not None else subprocess.DEVNULL,
            creationflags=NO_WINDOW,
        )
    finally:
        # El hijo ya tiene su propia copia del descriptor; esta se cierra.
        if archivo is not None:
            archivo.close()


def ultimas_lineas(ruta, cuantas: int = 8) -> str:
    """Las últimas líneas de un archivo de arranque, en una sola frase.

    Se descartan las decorativas (los `====` de los banners) porque lo que se
    busca es el motivo, y un banner ocupando seis de las ocho líneas es el
    motivo tapado.
    """
    try:
        crudo = Path(ruta).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    lineas = [linea.strip() for linea in crudo.splitlines() if linea.strip()]
    lineas = [linea for linea in lineas if set(linea) != {"="}]
    return " | ".join(lineas[-cuantas:])


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
        if len(parts) < 5 or parts[0].upper() != "LISTEN":
            continue
        # `ss -ltnp`: State Recv-Q Send-Q LocalAddress:Port PeerAddress:Port
        # ... La dirección local es el cuarto campo. Mirar cualquier campo
        # puede confundir un puerto remoto con el listener que queremos.
        local = parts[3]
        if ":" not in local or local.rsplit(":", 1)[-1] != str(port):
            continue
        for match in re.finditer(r"pid=(\d+)", line):
            pids.add(int(match.group(1)))
    return pids


def parse_netstat_linux_listening(output: str, port: int) -> set[int]:
    """PIDs de `netstat -ltnp` en Linux.

    El fallback de Linux antes reutilizaba `parse_ss_listening`, pero netstat
    no escribe ``pid=1234``: usa ``1234/programa``. En un Debian sin `ss`, el
    fallback por lo tanto devolvía siempre vacío.
    """
    pids: set[int] = set()
    for line in output.splitlines():
        parts = line.split()
        # tcp 0 0 127.0.0.1:8899 0.0.0.0:* LISTEN 1234/python
        if len(parts) < 7 or not parts[0].lower().startswith("tcp"):
            continue
        if parts[5].upper() != "LISTEN":
            continue
        local = parts[3]
        if ":" not in local or local.rsplit(":", 1)[-1] != str(port):
            continue
        pid_texto = parts[6].split("/", 1)[0]
        try:
            pid = int(pid_texto)
        except ValueError:
            continue
        if pid > 0:
            pids.add(pid)
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
        (["netstat", "-ltnp"], parse_netstat_linux_listening),
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


def port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """¿Hay algo escuchando ahí? Con un connect, no con `netstat`.

    ESTA FUNCIÓN ERA EL CUELLO DE BOTELLA DE TODO EL ORQUESTADOR.

    Llamaba a `listening_pids`, que corre `netstat -ano` y parsea la tabla de
    conexiones ENTERA de la máquina. En una PC con tráfico eso tarda entre
    medio segundo y dos. Y se llama en todos lados: para saber si un servicio
    está vivo, en cada vuelta de la espera de arranque, en cada vuelta de la
    verificación de que un puerto quedó libre.

    Encender el núcleo terminaba corriendo netstat decenas de veces para
    contestar seis preguntas de sí o no.

    Un connect a loopback contesta lo mismo en microsegundos. Un servicio que
    escucha en 0.0.0.0 también acepta por 127.0.0.1, así que cubre los dos
    casos de esta suite. `listening_pids` sigue existiendo y sigue usando
    netstat, pero solo se llama cuando de verdad hay que MATAR algo, que es
    cuando hace falta saber el PID.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.25)
        try:
            return s.connect_ex((host, int(port))) == 0
        except OSError:
            return False


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
    detalle) contando lo que realmente pasó.

    El camino feliz (el puerto ya estaba libre) no corre `netstat` ni una vez:
    se pregunta con un connect. Es el caso de casi todos los encendidos, y
    antes costaba una tabla de conexiones completa por cada puerto.
    """
    if not port_in_use(port):
        return True, f"puerto {port}: ya estaba libre"
    pids = listening_pids(port)
    if not pids:
        # Escucha algo pero no se pudo averiguar el PID: pasa cuando el
        # proceso es de otro usuario. Se dice, en vez de informar que quedó
        # libre.
        return False, (f"puerto {port} ocupado y no pude averiguar por quién "
                       "(¿es de otro usuario?)")

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
    # Con connect y no con netstat: son decenas de vueltas.
    fin = time.time() + timeout
    espera = 0.03
    while time.time() < fin:
        if not port_in_use(port):
            return True, f"puerto {port} liberado ({'; '.join(detalles)})"
        time.sleep(min(espera, max(0.0, fin - time.time())))
        espera = min(espera * 1.6, 0.25)

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
    """Espera a que algo empiece a escuchar en el puerto. Devuelve apenas aparece."""
    return not esperar_puertos({"": port}, timeout)


def esperar_puertos(puertos: dict, timeout: float = 8.0) -> list:
    """Espera a que TODOS empiecen a escuchar. Devuelve los que no llegaron.

    POR QUÉ TODOS JUNTOS Y NO UNO POR UNO

    Porque esperar en fila multiplica el peor caso por la cantidad. Con seis
    servicios y ocho segundos cada uno, un encendido donde nada arranca se
    quedaba 48 segundos mirando puertos, de a uno, cuando los seis ya se
    habían lanzado al mismo tiempo hacía rato. Mirándolos todos en cada vuelta,
    el peor caso vuelve a ser ocho segundos.

    No hacen falta hilos: preguntar por un puerto de loopback es un connect que
    tarda microsegundos, y seis por vuelta no se notan.

    EL INTERVALO CRECE

    Se arranca preguntando cada 30 ms y se va estirando hasta 250. Los
    servicios de esta suite abren su puerto en unos cientos de milisegundos
    cuando pueden, así que el caso normal termina en la primera décima de
    segundo en vez de esperar al primer tic de un cuarto de segundo. Y cuando
    algo no va a arrancar, el intervalo largo evita preguntar mil veces al
    pedo.
    """
    faltan = dict(puertos)
    fin = time.time() + timeout
    espera = 0.03
    while True:
        faltan = {nombre: port for nombre, port in faltan.items()
                  if not port_in_use(port)}
        if not faltan or time.time() >= fin:
            return list(faltan)
        time.sleep(min(espera, max(0.0, fin - time.time())))
        espera = min(espera * 1.6, 0.25)
