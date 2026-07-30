import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import securecenter.orchestrator as orch_mod  # noqa: E402
from securecenter.config_loader import load_config  # noqa: E402
from securecenter.logger_db import LoggerDB  # noqa: E402
from securecenter.orchestrator import CORE_AUTOSTART_TASK, Orchestrator  # noqa: E402
from securecenter.projects import discover_projects  # noqa: E402


def make_orch(fake_stack, tmp_path, windows=False, monkeypatch=None):
    root, _ = fake_stack
    cfg = load_config(str(tmp_path / "no.yaml"))
    projects = discover_projects(cfg, search_root=root)
    logger = LoggerDB(str(tmp_path / "c.db"))
    if windows and monkeypatch is not None:
        monkeypatch.setattr(orch_mod.platform, "system", lambda: "Windows")
    return Orchestrator(cfg, projects, logger, dry_run=True)


def labels(steps):
    return [s.label for s in steps]


def argvs(steps):
    return " || ".join(" ".join(s.argv) for s in steps)


def test_start_core_runs_proxy_and_dns_in_background(fake_stack, tmp_path):
    o = make_orch(fake_stack, tmp_path)
    steps = o.plan_start_core()
    text = argvs(steps)
    assert "run_proxy.py" in text
    assert "run_dns.py" in text
    # Los dos servicios quedan corriendo en segundo plano.
    bg = [s for s in steps if s.background]
    assert len(bg) == 2


def test_start_core_on_windows_sets_system_proxy_dns_and_autostart(fake_stack, tmp_path, monkeypatch):
    o = make_orch(fake_stack, tmp_path, windows=True, monkeypatch=monkeypatch)
    text = argvs(o.plan_start_core())
    assert "ProxyEnable" in text and "127.0.0.1:8888" in text  # el proxy del sistema apunta al puerto que proxea
    assert "Set-DnsClientServerAddress" in text and "127.0.0.1" in text  # DNS del sistema
    assert CORE_AUTOSTART_TASK in text  # inicio automatico


def test_system_proxy_excludes_localhost_bypass(fake_stack, tmp_path, monkeypatch):
    """LA línea que faltaba: sin el bypass de localhost, el navegador manda
    los dashboards locales a través del proxy y devuelve 502. Con
    ProxyOverride <local>, localhost sale directo."""
    o = make_orch(fake_stack, tmp_path, windows=True, monkeypatch=monkeypatch)
    text = argvs(o.plan_start_core())
    assert "ProxyOverride" in text
    assert "<local>" in text and "127.0.0.1" in text
    # el bypass se setea ANTES de activar el proxy
    lbls = labels(o.plan_start_core())
    assert lbls.index("proxy del sistema: excluir localhost (bypass)") < lbls.index("proxy del sistema: activar")


def test_start_core_order_service_before_system_setting(fake_stack, tmp_path, monkeypatch):
    """El proceso arranca ANTES de apuntarle el sistema, para que cuando el
    sistema empiece a usarlo ya esté escuchando."""
    o = make_orch(fake_stack, tmp_path, windows=True, monkeypatch=monkeypatch)
    lbls = labels(o.plan_start_core())
    assert lbls.index("iniciar SecureProxy") < lbls.index("proxy del sistema: activar")
    assert lbls.index("iniciar SecureDNS") < lbls.index("DNS del sistema: 127.0.0.1")


def test_start_vpn_delega_el_encendido_en_un_solo_script(fake_stack, tmp_path):
    """Encender la VPN es UN paso, no tres encadenados.

    Encadenar lab_up + provision + connect desde acá hacía que cada script
    arrancara apenas terminaba el anterior, sin espera en el medio: apt
    corría antes de que el contenedor tuviera red y ssh antes de que sshd
    aceptara sesiones. Por eso fallaba desde el dashboard y no desde el .bat
    de la VPN, donde uno tarda en apretar la opción siguiente.
    start_vpn.py hace las etapas con las esperas adentro."""
    o = make_orch(fake_stack, tmp_path)
    text = argvs(o.plan_start_vpn())
    assert "start_vpn.py" in text
    assert "lab_up.py" not in text
    assert "provision_server.py" not in text
    # el dashboard sigue arrancando primero, para poder mirar el progreso
    assert text.index("run_dashboard.py") < text.index("start_vpn.py")


def test_el_encendido_de_la_vpn_tiene_timeout_largo(fake_stack, tmp_path):
    """La primera vez hay que esperar a que arranque Docker Desktop y a que
    se construya la imagen del laboratorio: con el timeout normal de 10
    minutos se cortaba a mitad de camino."""
    o = make_orch(fake_stack, tmp_path)
    encendido = [s for s in o.plan_start_vpn() if "start_vpn.py" in " ".join(s.argv)]
    assert encendido and encendido[0].timeout >= 1200


def test_start_core_kills_ports_before_running_service(fake_stack, tmp_path, monkeypatch):
    """Robustez: antes de arrancar, libera los puertos del núcleo - evita dos
    instancias peleando (la causa del 'stop no encuentra la instancia real'
    que reportó el QA)."""
    o = make_orch(fake_stack, tmp_path, windows=True, monkeypatch=monkeypatch)
    lbls = labels(o.plan_start_core())
    assert lbls.index("liberar puertos del núcleo (instancias previas)") < lbls.index("iniciar SecureProxy")


def test_port_steps_run_in_python_not_powershell(fake_stack, tmp_path, monkeypatch):
    """Velocidad y ventanas: liberar/verificar puertos se hace en Python (paso
    con func), no con PowerShell - que tarda ~1s en arrancar y abre una
    ventana que parpadea."""
    o = make_orch(fake_stack, tmp_path, windows=True, monkeypatch=monkeypatch)
    for plan in (o.plan_start_core(), o.plan_stop_core()):
        assert "Stop-Process" not in argvs(plan)
        assert "Get-NetTCPConnection" not in argvs(plan)
        funcs = [s for s in plan if s.func is not None]
        assert funcs, "deberia haber pasos hechos en Python"


def test_port_and_verify_steps_are_not_optional(fake_stack, tmp_path, monkeypatch):
    """Honestidad: si liberar un puerto falla, NO se puede informar OK (era
    el bug de '-ErrorAction SilentlyContinue': decia OK y seguia prendido)."""
    o = make_orch(fake_stack, tmp_path, windows=True, monkeypatch=monkeypatch)
    for plan in (o.plan_start_core(), o.plan_stop_core()):
        for step in plan:
            if step.func is not None:
                assert not step.optional


def test_plans_end_with_verification(fake_stack, tmp_path, monkeypatch):
    """Cada plan termina verificando el resultado real, no asumiendolo."""
    o = make_orch(fake_stack, tmp_path, windows=True, monkeypatch=monkeypatch)
    assert labels(o.plan_start_core())[-1] == "verificar que quedó encendido"
    assert labels(o.plan_stop_core())[-1] == "verificar que quedó apagado"
    assert labels(o.plan_stop_one("proxy"))[-1] == "verificar que quedó apagado"
    assert labels(o.plan_start_one("dns"))[-1] == "verificar que quedó encendido"


def test_stop_one_removes_autostart_before_killing(fake_stack, tmp_path, monkeypatch):
    """Si la tarea de inicio automatico sigue viva, puede relanzar el servicio
    justo despues de matarlo y parecer que apagar 'no hizo nada'."""
    o = make_orch(fake_stack, tmp_path, windows=True, monkeypatch=monkeypatch)
    lbls = labels(o.plan_stop_one("proxy"))
    assert lbls.index("quitar autostart viejo de SecureProxy") < lbls.index(
        "asegurar puerto 8888 cerrado (SecureProxy)"
    )


def test_start_core_removes_old_per_project_autostart(fake_stack, tmp_path, monkeypatch):
    """SecureCenter toma el control: saca los autostart propios de proxy/dns
    para que no resuciten los servicios en cada login."""
    o = make_orch(fake_stack, tmp_path, windows=True, monkeypatch=monkeypatch)
    text = argvs(o.plan_start_core())
    assert "SecureProxyAutostart" in text
    assert "SecureDNSAutostart" in text


def test_stop_core_kills_ports_and_removes_old_tasks(fake_stack, tmp_path, monkeypatch):
    """Apagar de verdad: mata por PUERTO (no por PID, que puede quedar viejo)
    y saca los autostart viejos de cada proyecto."""
    o = make_orch(fake_stack, tmp_path, windows=True, monkeypatch=monkeypatch)
    plan = o.plan_stop_core()
    text = argvs(plan)
    # los puertos del núcleo se liberan en un paso de Python
    assert any("puertos del núcleo" in s.label and s.func for s in plan)
    assert "SecureProxyAutostart" in text and "SecureDNSAutostart" in text


def test_stop_vpn_kills_its_dashboard_port(fake_stack, tmp_path, monkeypatch):
    o = make_orch(fake_stack, tmp_path, windows=True, monkeypatch=monkeypatch)
    plan = o.plan_stop_vpn()
    assert any("8891" in s.label and s.func is not None for s in plan)
    assert "SecureVPNDashboardAutostart" in argvs(plan)


def test_start_vpn_also_starts_its_dashboard(fake_stack, tmp_path):
    """Sin esto, SecureCenter prende la VPN pero su dashboard (8891) nunca
    sube, y el chequeo de salud la ve 'apagado' aunque el túnel conecte."""
    o = make_orch(fake_stack, tmp_path)
    steps = o.plan_start_vpn()
    dash = [s for s in steps if "run_dashboard.py" in " ".join(s.argv)]
    assert len(dash) == 1
    assert dash[0].background  # el dashboard queda corriendo


def test_stop_all_includes_vpn_when_running(fake_stack, tmp_path):
    o = make_orch(fake_stack, tmp_path)
    text = argvs(o.plan_stop_all(vpn_was_running=True))
    assert "disconnect_vpn.py" in text
    assert "lab_down.py" in text
    assert "stop_dns.py" in text
    assert "stop_proxy.py" in text


def test_stop_all_omits_vpn_when_not_running(fake_stack, tmp_path):
    """Si la VPN no se prendió, se omite su parte pero igual se apaga el
    núcleo y se saca su inicio automático - tal como se pidió."""
    o = make_orch(fake_stack, tmp_path)
    steps = o.plan_stop_all(vpn_was_running=False)
    text = argvs(steps)
    assert "disconnect_vpn.py" not in text
    assert "lab_down.py" not in text
    assert "stop_dns.py" in text
    assert "stop_proxy.py" in text


def test_panic_restores_internet_first(fake_stack, tmp_path):
    o = make_orch(fake_stack, tmp_path)
    text = argvs(o.plan_panic())
    assert "restore_internet.py" in text
    # restore va antes de bajar el laboratorio
    assert text.index("restore_internet.py") < text.index("lab_down.py")


def test_stop_steps_are_optional(fake_stack, tmp_path):
    """Apagar algo que no estaba corriendo no debe hacer fallar la operación."""
    o = make_orch(fake_stack, tmp_path)
    assert all(s.optional for s in o.plan_stop_vpn())


def test_execute_dry_run_touches_nothing(fake_stack, tmp_path):
    o = make_orch(fake_stack, tmp_path)
    result = o.execute(o.plan_start_core(), "start_core")
    assert result.ok
    assert all("[dry-run]" in line for line in result.lines)


def test_individual_plans(fake_stack, tmp_path):
    o = make_orch(fake_stack, tmp_path)
    assert "run_proxy.py" in argvs(o.plan_start_one("proxy"))
    assert "stop_dns.py" in argvs(o.plan_stop_one("dns"))
    assert "start_vpn.py" in argvs(o.plan_start_one("vpn"))
    assert o.plan_start_one("inexistente") == []


def test_docker_proxy_conflict_is_diagnosed():
    """El error real que vio el usuario: Docker no puede bajar la imagen
    porque hereda el proxy del sistema y desde su VM no lo alcanza. El
    mensaje crudo no lo explica; la pista sí."""
    from securecenter.orchestrator import diagnosticar

    lineas = [
        "ERROR: VPN: levantar laboratorio -> failed to resolve source metadata "
        "for docker.io/library/ubuntu:24.04: failed to do request"
    ]
    pistas = diagnosticar(lineas)
    assert pistas, "deberia detectar el conflicto Docker/proxy"
    assert "Docker Desktop" in pistas[0]
    assert "proxy" in pistas[0].lower()


def test_no_false_diagnosis_on_clean_run():
    from securecenter.orchestrator import diagnosticar

    assert diagnosticar(["OK: iniciar SecureProxy", "OK: verificado"]) == []


def test_execute_va_avisando_paso_a_paso(fake_stack, tmp_path):
    """El orquestador ahora emite cada linea APENAS pasa, en vez de devolver
    todo junto al final: es lo que alimenta la consola en vivo."""
    o = make_orch(fake_stack, tmp_path)
    o.dry_run = True
    vistas = []

    res = o.execute(o.plan_start_core(), "start_core", progress=vistas.append)

    assert vistas, "no emitio nada mientras corria"
    assert vistas == res.lines, "lo emitido en vivo y el resultado final coinciden"


def test_los_scripts_corren_sin_buffer(fake_stack, tmp_path):
    """Sin `-u`, Python acumula lo que imprime cuando la salida va a una
    tuberia, y la consola en vivo recibiria todo de golpe al final."""
    o = make_orch(fake_stack, tmp_path)
    pasos = [s for s in o.plan_start_vpn() if s.argv]

    assert pasos, "no hay pasos con comando"
    for paso in pasos:
        assert "-u" in paso.argv, f"falta -u en {paso.label}"
