import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securecenter import procutil  # noqa: E402
from securecenter.procutil import (  # noqa: E402
    NO_WINDOW,
    free_port,
    listening_pids,
    parse_netstat_listening,
    port_in_use,
    wait_port_listening,
)

# Salida real de `netstat -ano` en Windows (formato con el que se trabaja).
NETSTAT_SAMPLE = """
Conexiones activas

  Proto  Dirección local        Dirección remota       Estado           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1234
  TCP    127.0.0.1:8888         0.0.0.0:0              LISTENING       56020
  TCP    127.0.0.1:8890         0.0.0.0:0              LISTENING       51072
  TCP    127.0.0.1:58177        127.0.0.1:8888         TIME_WAIT       0
  TCP    192.168.0.10:58899     116.202.120.181:443    ESTABLISHED     7777
  TCP    [::]:8888              [::]:0                 LISTENING       56020
"""


def test_parse_finds_only_listening_pid_for_that_port():
    assert parse_netstat_listening(NETSTAT_SAMPLE, 8888) == {56020}
    assert parse_netstat_listening(NETSTAT_SAMPLE, 8890) == {51072}


def test_parse_ignores_non_listening_and_remote_ports():
    """El 8888 aparece también como puerto REMOTO en una línea TIME_WAIT: no
    debe contar (matar ese PID sería matar al cliente, no al servicio)."""
    pids = parse_netstat_listening(NETSTAT_SAMPLE, 8888)
    assert 0 not in pids
    assert 7777 not in pids


def test_parse_ignores_similar_port_numbers():
    """58899 contiene '889' pero no es el 8899: filtrar por texto suelto
    mataría procesos ajenos."""
    assert parse_netstat_listening(NETSTAT_SAMPLE, 8899) == set()


def test_parse_empty_output():
    assert parse_netstat_listening("", 8888) == set()


def test_no_window_flag_is_zero_outside_windows():
    import platform

    if platform.system() != "Windows":
        assert NO_WINDOW == 0


def test_port_in_use_detects_real_listener():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        assert port_in_use(port) is True
    finally:
        listener.close()


def test_free_port_on_already_free_port_reports_success():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    ok, detalle = free_port(port, timeout=2)
    assert ok
    assert "libre" in detalle


def test_free_port_kills_real_process_and_verifies():
    """Prueba de verdad: levanta un proceso hijo que escucha un puerto, lo
    mata con free_port, y confirma que el puerto quedó libre. Es exactamente
    el camino del botón 'Apagar SecureProxy'."""
    code = (
        "import socket,time;"
        "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
        "s.bind(('127.0.0.1',PORT));s.listen(5);"
        "print('listo',flush=True);time.sleep(120)"
    )
    # puerto libre elegido por el SO
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    proc = subprocess.Popen(
        [sys.executable, "-c", code.replace("PORT", str(port))],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )
    try:
        assert wait_port_listening(port, timeout=10), "el proceso de prueba no llegó a escuchar"
        assert listening_pids(port)  # lo ve por netstat

        ok, detalle = free_port(port, timeout=10)

        if not ok and ("acceso denegado" in detalle.lower()
                       or "administrador" in detalle.lower()):
            pytest.skip(f"sandbox sin permiso para terminar procesos: {detalle}")
        assert ok, f"free_port dijo que falló: {detalle}"
        assert not port_in_use(port), "el puerto sigue ocupado tras free_port"
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=10)


def test_wait_port_listening_times_out_when_nothing_starts():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    inicio = time.time()
    assert wait_port_listening(port, timeout=1.0) is False
    assert time.time() - inicio < 3  # no se cuelga


def test_windows_service_running_is_false_outside_windows():
    """La deteccion del tunel de WireGuard (servicio de Windows) no aplica en
    Linux: debe responder False sin romperse, no lanzar excepcion."""
    from securecenter.procutil import windows_service_running

    import platform
    if platform.system() != "Windows":
        assert windows_service_running("WireGuardTunnel$securevpn") is False


def _ocupado_segun_pids(monkeypatch):
    """`port_in_use` pregunta con un connect y `listening_pids` con netstat.

    Son dos fuentes distintas a propósito (la primera es microsegundos, la
    segunda es una tabla de conexiones entera), así que en un test que simula
    un puerto ocupado hay que hacer que las dos digan lo mismo.
    """
    monkeypatch.setattr(procutil, "port_in_use",
                        lambda port, host="127.0.0.1": bool(procutil.listening_pids(port)))


def test_free_port_pide_permisos_cuando_le_deniegan_el_acceso(monkeypatch):
    """El caso real: el nucleo se prende desde SecureCenter.bat (elevado) y
    el dashboard arranca con Windows sin elevar, asi que taskkill devuelve
    'acceso denegado'. En vez de rendirse, se pide UAC una sola vez."""
    _ocupado_segun_pids(monkeypatch)
    monkeypatch.setattr(procutil, "is_windows", lambda: True)
    monkeypatch.setattr(procutil, "is_admin", lambda: False)

    estado = {"vivo": True}
    monkeypatch.setattr(
        procutil, "listening_pids",
        lambda port: {4242} if estado["vivo"] else set(),
    )
    monkeypatch.setattr(
        procutil, "kill_pid",
        lambda pid: (False, f"acceso denegado al matar el proceso {pid}"),
    )

    elevados = []

    def fake_elevated(argv, espera_maxima=30.0):
        elevados.append(argv)
        estado["vivo"] = False  # el taskkill elevado si pudo
        return True, "ejecutado con permisos de administrador"

    monkeypatch.setattr(procutil, "run_elevated", fake_elevated)

    ok, detalle = procutil.free_port(8888, timeout=2)

    assert ok, detalle
    assert elevados, "tendria que haber pedido permisos de administrador"
    assert "4242" in " ".join(elevados[0])
    assert "/F" in elevados[0] and "/T" in elevados[0]


def test_no_pide_permisos_si_ya_es_administrador(monkeypatch):
    """Si ya esta elevado y aun asi no pudo, pedir UAC no arregla nada y
    solo molesta con un cartel inutil."""
    _ocupado_segun_pids(monkeypatch)
    monkeypatch.setattr(procutil, "is_windows", lambda: True)
    monkeypatch.setattr(procutil, "is_admin", lambda: True)
    monkeypatch.setattr(procutil, "listening_pids", lambda port: {4242})
    monkeypatch.setattr(procutil, "kill_pid", lambda pid: (False, "acceso denegado"))
    monkeypatch.setattr(
        procutil, "run_elevated",
        lambda *a, **k: pytest.fail("no deberia pedir UAC estando elevado"),
    )

    ok, _detalle = procutil.free_port(8888, timeout=1)

    assert not ok


def test_una_sola_ventana_de_uac_para_varios_procesos(monkeypatch):
    """Dos instancias colgadas en el mismo puerto no pueden significar dos
    carteles de UAC seguidos."""
    _ocupado_segun_pids(monkeypatch)
    monkeypatch.setattr(procutil, "is_windows", lambda: True)
    monkeypatch.setattr(procutil, "is_admin", lambda: False)
    estado = {"vivo": True}
    monkeypatch.setattr(
        procutil, "listening_pids",
        lambda port: {111, 222} if estado["vivo"] else set(),
    )
    monkeypatch.setattr(procutil, "kill_pid", lambda pid: (False, "acceso denegado"))

    elevados = []

    def fake_elevated(argv, espera_maxima=30.0):
        elevados.append(argv)
        estado["vivo"] = False
        return True, "ok"

    monkeypatch.setattr(procutil, "run_elevated", fake_elevated)
    procutil.free_port(8888, timeout=2)

    assert len(elevados) == 1, "un solo pedido de permisos, no uno por proceso"
    assert "111" in " ".join(elevados[0]) and "222" in " ".join(elevados[0])


def test_si_el_usuario_cancela_el_uac_se_informa_de_verdad(monkeypatch):
    _ocupado_segun_pids(monkeypatch)
    monkeypatch.setattr(procutil, "is_windows", lambda: True)
    monkeypatch.setattr(procutil, "is_admin", lambda: False)
    monkeypatch.setattr(procutil, "listening_pids", lambda port: {4242})
    monkeypatch.setattr(procutil, "kill_pid", lambda pid: (False, "acceso denegado"))
    monkeypatch.setattr(
        procutil, "run_elevated",
        lambda *a, **k: (False, "cancelaste el pedido de permisos de administrador"),
    )

    ok, detalle = procutil.free_port(8888, timeout=1)

    assert not ok
    assert "SIGUE ocupado" in detalle


def test_parse_netstat_linux_fallback():
    salida = """
tcp        0      0 127.0.0.1:8899        0.0.0.0:*               LISTEN      1234/python3
tcp6       0      0 :::8890                 :::*                    LISTEN      2222/python3
"""
    assert procutil.parse_netstat_linux_listening(salida, 8899) == {1234}
    assert procutil.parse_netstat_linux_listening(salida, 8890) == {2222}


def test_parse_ss_no_confunde_puerto_remoto():
    salida = (
        'LISTEN 0 128 127.0.0.1:9000 127.0.0.1:8899 '
        'users:(("python",pid=4444,fd=3))\n'
    )
    assert procutil.parse_ss_listening(salida, 8899) == set()


# ================== velocidad: no correr netstat para nada ==================

def test_port_in_use_no_corre_netstat(monkeypatch):
    """ERA EL CUELLO DE BOTELLA DE TODO EL ORQUESTADOR.

    Llamaba a `listening_pids`, que corre `netstat -ano` y parsea la tabla de
    conexiones ENTERA de la máquina. Y se llama en todos lados: para saber si
    un servicio está vivo, en cada vuelta de la espera de arranque, en cada
    vuelta de la verificación de que un puerto quedó libre. Encender el núcleo
    terminaba corriendo netstat decenas de veces para contestar seis preguntas
    de sí o no.
    """
    def no_deberia(*_a, **_k):
        raise AssertionError("port_in_use no puede correr un proceso externo")

    monkeypatch.setattr(procutil, "run_quiet", no_deberia)
    monkeypatch.setattr(procutil, "listening_pids", no_deberia)
    assert procutil.port_in_use(9) in (True, False)


def test_un_puerto_libre_se_libera_sin_netstat(monkeypatch):
    """El camino feliz de "liberar puertos" es que ya estaban libres, y es el
    de casi todos los encendidos. Antes costaba una tabla de conexiones
    completa por cada puerto."""
    monkeypatch.setattr(procutil, "port_in_use", lambda *_a, **_k: False)
    monkeypatch.setattr(procutil, "listening_pids",
                        lambda _p: (_ for _ in ()).throw(
                            AssertionError("no hacía falta netstat")))
    ok, detalle = procutil.free_port(9999)
    assert ok and "ya estaba libre" in detalle


def test_esperar_puertos_los_mira_a_todos_en_cada_vuelta(monkeypatch):
    """Esperar en fila multiplica el peor caso por la cantidad: seis servicios
    por ocho segundos eran 48 segundos mirando puertos de a uno, cuando los
    seis ya se habían lanzado juntos hacía rato."""
    vueltas = {"n": 0}

    def falso(port, host="127.0.0.1"):
        vueltas["n"] += 1
        # El 8891 nunca abre; los otros abren enseguida.
        return port != 8891

    monkeypatch.setattr(procutil, "port_in_use", falso)
    inicio = time.time()
    faltan = procutil.esperar_puertos(
        {"a": 8888, "b": 8890, "c": 8892, "d": 8893, "e": 8894, "f": 8891},
        timeout=1)
    tardo = time.time() - inicio

    assert faltan == ["f"]
    # Un solo timeout para todos, no uno por cada uno.
    assert tardo < 1.6, f"tardó {tardo:.2f}s: parece que esperó en fila"


def test_esperar_puertos_devuelve_apenas_estan_todos(monkeypatch):
    """El intervalo arranca en 30 ms: los servicios de esta suite abren su
    puerto en unos cientos de milisegundos, y esperar al primer tic de un
    cuarto de segundo era regalar tiempo en el caso normal."""
    monkeypatch.setattr(procutil, "port_in_use", lambda *_a, **_k: True)
    inicio = time.time()
    assert procutil.esperar_puertos({"a": 1, "b": 2}, timeout=5) == []
    assert time.time() - inicio < 0.1
