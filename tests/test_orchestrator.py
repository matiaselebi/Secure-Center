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
    """Todo lo que el plan va a tocar, en texto.

    Incluye `objetivo` además del argv porque desde la capa de arranque hay
    pasos que no son un comando externo sino una función que llama al backend
    del sistema (schtasks en Windows, systemd en Linux). El nombre de la tarea
    o de la unidad viaja en `objetivo`, y sin él estos tests dejarían de
    verificar justamente lo que vienen a verificar: que se quiten los
    autostart correctos.
    """
    return " || ".join(
        " ".join(list(s.argv) + ([s.objetivo] if s.objetivo else []))
        for s in steps
    )


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
    # El DNS ya no se toca con un PowerShell escrito acá: se delega en el
    # net_config.py de SecureDNS, que además guarda el DNS anterior y deja un
    # respaldo detrás del nuestro. Tener dos copias del mismo comando fue el
    # bug: SecureDNS aprendió a hacerlo bien y SecureCenter siguió a pelo.
    assert "net_config" in text and "tomar_el_dns_si_corresponde" in text
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
    dns = next(l for l in lbls if l.startswith("DNS del sistema:"))
    assert lbls.index("iniciar SecureDNS") < lbls.index(dns)


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


# Pasos hechos en Python que SÍ pueden ser opcionales, con el motivo al lado.
# La lista es explícita a propósito: agregar uno nuevo obliga a justificarlo
# acá, en vez de que la excepción se cuele sola.
PASOS_QUE_PUEDEN_FALLAR = {
    # Avisarle al navegador que cambió el proxy es una cortesía: si falla, el
    # navegador toma la configuración nueva igual al reiniciarse. No afecta si
    # la protección quedó puesta o no, que es lo que este test cuida.
    "avisar al navegador del cambio de proxy",
}


def _es_quitar_autostart(step) -> bool:
    """Quitar un arranque automático puede fallar sin que sea un problema.

    Desde la capa de arranque estos pasos son funciones (llaman a schtasks o a
    systemd según el sistema), así que caen bajo la regla de este test. La
    excepción es legítima y no una escapatoria: quitar algo que no está
    devuelve éxito, y el único fallo real posible es no poder borrar un
    archivo de unidad por permisos. Que eso frene el apagado entero sería
    peor que seguir: los servicios quedarían prendidos por no haber podido
    borrar una configuración de arranque.
    """
    return "autostart" in step.label.lower() or "inicio automático" in step.label.lower()


def test_port_and_verify_steps_are_not_optional(fake_stack, tmp_path, monkeypatch):
    """Honestidad: si liberar un puerto falla, NO se puede informar OK (era
    el bug de '-ErrorAction SilentlyContinue': decia OK y seguia prendido).

    Vale para todo paso hecho en Python salvo los de PASOS_QUE_PUEDEN_FALLAR,
    que son los que no dicen nada sobre si quedó prendido o apagado.
    """
    o = make_orch(fake_stack, tmp_path, windows=True, monkeypatch=monkeypatch)
    for plan in (o.plan_start_core(), o.plan_stop_core()):
        for step in plan:
            if (step.func is not None
                    and step.label not in PASOS_QUE_PUEDEN_FALLAR
                    and not _es_quitar_autostart(step)):
                assert not step.optional, step.label


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
    steps = o.plan_stop_vpn()
    assert all(s.optional for s in steps if not s.label.startswith("asegurar puerto"))
    assert any(not s.optional for s in steps if s.label.startswith("asegurar puerto"))


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


def test_el_dns_del_sistema_lo_pone_securedns_y_no_securecenter(fake_stack, tmp_path, monkeypatch):
    """Tener el mismo comando escrito en dos lados fue el bug real.

    SecureDNS aprendió a guardar el DNS anterior y a dejar un respaldo detrás
    del nuestro (para no quedarse sin internet en el arranque), y SecureCenter
    siguió pisando los adaptadores con 127.0.0.1 a secas. Encender el núcleo
    desde el panel te dejaba expuesto; desde el .bat, no.
    """
    o = make_orch(fake_stack, tmp_path, windows=True, monkeypatch=monkeypatch)
    encender = argvs(o.plan_start_core())
    assert "tomar_el_dns_si_corresponde" in encender
    assert "-ServerAddresses '127.0.0.1'" not in encender
    apagar = argvs(o.plan_stop_core())
    assert ("devolver_el_dns_si_corresponde" in apagar
            or "ResetServerAddresses" in apagar)


def test_un_paso_python_obligatorio_que_falla_corta_el_plan(fake_stack, tmp_path):
    """No se puede seguir arrancando si, por ejemplo, no se liberó el puerto."""
    from securecenter.orchestrator import Step

    o = make_orch(fake_stack, tmp_path)
    o.dry_run = False
    ejecutado = []
    pasos = [
        Step("falla obligatoria", [], func=lambda: (False, "no pude liberar")),
        Step("no debe correr", [], func=lambda: (ejecutado.append(True) or (True, "ok"))),
    ]

    resultado = o.execute(pasos, "test_func_fail")

    assert not resultado.ok
    assert ejecutado == []
    assert any("ERROR: falla obligatoria" in linea for linea in resultado.lines)


def test_en_un_servidor_el_nucleo_no_prende_el_proxy_pero_lo_dice(fake_stack, tmp_path, monkeypatch):
    """Fase 1 del punto 8.

    Lo importante no es que no lo prenda: es que se vea POR QUÉ. Un plan que
    simplemente omite el proxy es indistinguible de un plan roto, y el que lo
    mira se queda pensando que SecureProxy no le anda.
    """
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr("securecenter.capacidades.platform.system", lambda: "Linux")

    o = make_orch(fake_stack, tmp_path)
    steps = o.plan_start_core()
    assert "run_proxy.py" not in argvs(steps)

    etiquetas = " ".join(s.label for s in steps)
    assert "Alcance de SecureProxy" in etiquetas
    # El resto del núcleo sigue prendiéndose igual.
    assert "run_dns.py" in argvs(steps)


def test_el_boton_del_proxy_igual_lo_prende_en_un_servidor(fake_stack, tmp_path, monkeypatch):
    """Apretar el botón es una orden de una persona, no el plan automático.
    Hay un caso legítimo (mirar qué sale del propio servidor) y negárselo a
    quien lo pidió a mano sería decidir por él."""
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr("securecenter.capacidades.platform.system", lambda: "Linux")

    o = make_orch(fake_stack, tmp_path)
    assert "run_proxy.py" in argvs(o.plan_start_one("proxy"))


# ============ que TODOS los proyectos se puedan prender y apagar ============

def _orq_completo(raiz, tmp_path):
    from securecenter.config_loader import Config
    from securecenter.logger_db import LoggerDB
    from securecenter.projects import discover_projects

    cfg = Config()
    return Orchestrator(cfg, discover_projects(cfg, raiz),
                        LoggerDB(str(tmp_path / "center.db")))


def test_la_tabla_del_nucleo_cubre_todos_los_proyectos():
    """Si mañana entra un proyecto nuevo, este test falla acá y no en el panel
    del usuario tres reinicios después."""
    from securecenter.orchestrator import SERVICIOS_DEL_NUCLEO
    from securecenter.projects import PROJECT_SPECS

    # La tabla del núcleo cubre a todos menos la VPN, que tiene su propio
    # camino (laboratorio, aprovisionar, conectar) y no es un run/stop simple.
    claves = {s.key for s in PROJECT_SPECS} - {"vpn"}
    assert {s[0] for s in SERVICIOS_DEL_NUCLEO} == claves


@pytest.mark.parametrize("key", [s.key for s in __import__(
    "securecenter.projects", fromlist=["PROJECT_SPECS"]).PROJECT_SPECS])
def test_todo_proyecto_se_puede_prender_y_apagar(stack_completo, tmp_path, key):
    """EL test que faltaba.

    `plan_stop_one("scanner")` tiraba KeyError porque Secure-Scanner no tiene
    tarea de autostart propia y el diccionario se leía con corchetes. Como eso
    pasaba adentro del hilo de fondo del panel, el botón "Apagar" no hacía
    absolutamente nada y no aparecía ningún error en ningún lado.

    Parametrizado sobre PROJECT_SPECS y no sobre una lista escrita a mano: el
    proyecto que se agregue mañana entra solo.
    """
    o = _orq_completo(stack_completo, tmp_path)
    assert o.plan_start_one(key), f"no hay plan para encender {key}"
    assert o.plan_stop_one(key), f"no hay plan para apagar {key}"


def test_apagar_todo_apaga_tambien_los_de_afuera_del_nucleo(stack_completo, tmp_path):
    """Un botón que dice TODO y deja dos servicios corriendo es la clase de
    mentira que hace que después nadie confíe en el panel."""
    o = _orq_completo(stack_completo, tmp_path)
    texto = argvs(o.plan_stop_all(vpn_was_running=False))
    assert "stop_scanner.py" in texto
    assert "stop_servidor.py" in texto


def test_el_panico_tambien_los_apaga(stack_completo, tmp_path):
    o = _orq_completo(stack_completo, tmp_path)
    texto = argvs(o.plan_panic())
    assert "stop_scanner.py" in texto and "stop_servidor.py" in texto


def test_encender_verifica_que_haya_quedado_vivo(stack_completo, tmp_path):
    """Estaba detrás de un `if _is_windows()`, y ese if era el que hacía que un
    servicio que arranca y se muere al segundo se viera igual que uno
    encendido: el plan salía todo en verde y el panel decía "apagado"."""
    o = _orq_completo(stack_completo, tmp_path)
    etiquetas = [s.label for s in o.plan_start_one("scanner")]
    assert "verificar que quedó encendido" in etiquetas


# ----------------------- el secreto que falta, dicho de frente

def test_sin_token_el_agente_no_se_lanza_y_se_explica(stack_completo, tmp_path,
                                                      monkeypatch):
    """Secure-Agent no arranca sin token, y hace bien: un token por defecto es
    un token público. El problema era otro: se lanza en segundo plano, imprime
    el motivo en una consola que nadie ve, devuelve 1 y se muere. Desde el
    panel eso se veía EXACTAMENTE igual que "nunca arrancó"."""
    monkeypatch.delenv("SECUREAGENT_TOKEN", raising=False)
    o = _orq_completo(stack_completo, tmp_path)

    pasos = o.plan_start_one("agente")
    assert "run_servidor.py" not in argvs(pasos)
    ok, detalle = pasos[0].func()
    assert not ok
    assert "SECUREAGENT_TOKEN" in detalle
    assert ".env" in detalle
    # Y dice cómo generarlo, no solo que falta.
    assert "secrets" in detalle


def test_con_el_token_en_el_env_del_proyecto_arranca(stack_completo, tmp_path,
                                                     monkeypatch):
    """El token vive en el .env del proyecto, no en el entorno de quien abre
    el panel. Es donde lo va a poner cualquiera que siga el README."""
    monkeypatch.delenv("SECUREAGENT_TOKEN", raising=False)
    (stack_completo / "carpeta-agente" / ".env").write_text(
        "SECUREAGENT_TOKEN=abc123\n", encoding="utf-8")
    o = _orq_completo(stack_completo, tmp_path)
    assert "run_servidor.py" in argvs(o.plan_start_one("agente"))


def test_un_env_con_la_clave_vacia_cuenta_como_que_falta(stack_completo, tmp_path,
                                                         monkeypatch):
    """`SECUREAGENT_TOKEN=` es el caso más fácil de dejar a medias: copiaste el
    .env.example y no lo completaste."""
    monkeypatch.delenv("SECUREAGENT_TOKEN", raising=False)
    (stack_completo / "carpeta-agente" / ".env").write_text(
        "SECUREAGENT_TOKEN=\n", encoding="utf-8")
    o = _orq_completo(stack_completo, tmp_path)
    assert "run_servidor.py" not in argvs(o.plan_start_one("agente"))


def test_a_los_demas_proyectos_no_se_les_pide_ningun_secreto(stack_completo,
                                                             tmp_path, monkeypatch):
    monkeypatch.delenv("SECUREAGENT_TOKEN", raising=False)
    o = _orq_completo(stack_completo, tmp_path)
    assert "run_scanner.py" in argvs(o.plan_start_one("scanner"))


# ------------- los seis del núcleo, sin condiciones

def test_el_nucleo_prende_los_seis(stack_completo, tmp_path, monkeypatch):
    """"Encender núcleo" tiene que prender el núcleo.

    Hubo una versión con una puerta que dejaba entrar a Secure-Scanner y a
    Secure-Agent solo si estaban configurados. Se sacó: que la lista de lo que
    prende dependa de tres condiciones invisibles es peor que el problema que
    resolvía. Si a alguno le falta algo, se dice y los otros cinco siguen.
    """
    monkeypatch.setenv("SECUREAGENT_TOKEN", "abc123")
    o = _orq_completo(stack_completo, tmp_path)
    texto = argvs(o.plan_start_core())
    for script in ("run_proxy.py", "run_dns.py", "run_hips.py", "run_intel.py",
                   "run_scanner.py", "run_servidor.py"):
        assert script in texto, script


def test_la_vpn_sigue_siendo_la_unica_afuera(stack_completo, tmp_path, monkeypatch):
    """Mete todo tu tráfico por un túnel y en modo laboratorio rompe cosas
    sensibles al NAT, como los juegos online. Es la única que se justifica."""
    monkeypatch.setenv("SECUREAGENT_TOKEN", "abc123")
    o = _orq_completo(stack_completo, tmp_path)
    texto = argvs(o.plan_start_core())
    assert "connect_vpn.py" not in texto and "lab_up.py" not in texto


def test_apagar_el_nucleo_apaga_los_seis(stack_completo, tmp_path, monkeypatch):
    monkeypatch.setenv("SECUREAGENT_TOKEN", "abc123")
    o = _orq_completo(stack_completo, tmp_path)
    texto = argvs(o.plan_stop_core())
    assert "stop_scanner.py" in texto and "stop_servidor.py" in texto


def test_sus_puertos_entran_en_el_kill_y_en_la_verificacion(stack_completo, tmp_path):
    """Si entran al núcleo entran del todo: el kill de instancias previas y la
    verificación final los tienen que incluir, o quedan a medio camino."""
    o = _orq_completo(stack_completo, tmp_path)
    puertos = o._puertos_del_nucleo()
    assert puertos["scanner"] == 8894
    # El de INGESTA, que es el que dice si está vivo, no el panel que no tiene.
    assert puertos["agente"] == 8895


def test_sin_token_el_nucleo_arranca_igual_y_lo_dice(stack_completo, tmp_path,
                                                     monkeypatch):
    """Que a Secure-Agent le falte el token no puede impedir que arranquen los
    otros cinco. Pero tampoco puede saltearse callado: el paso sale, dice qué
    falta, y es opcional para no marcar el plan entero como fallado."""
    monkeypatch.delenv("SECUREAGENT_TOKEN", raising=False)
    o = _orq_completo(stack_completo, tmp_path)
    pasos = o.plan_start_core()

    assert "run_servidor.py" not in argvs(pasos)
    assert "run_scanner.py" in argvs(pasos)
    paso = next(s for s in pasos if "SECUREAGENT_TOKEN" in s.label)
    assert paso.optional
    ok, detalle = paso.func()
    assert not ok and ".env" in detalle


# ------------------------------ preparar: crear venv y token que faltan

def _preparar():
    """El script se carga sin sus imports de entorno, para probar sus piezas.

    Se prueban las funciones y no el `main`, que necesita proyectos reales en
    disco. Lo que importa acá es que sean idempotentes: nadie corre esto una
    sola vez.
    """
    fuente = (Path(__file__).resolve().parent.parent / "scripts"
              / "preparar.py").read_text(encoding="utf-8")
    fuente = fuente.replace("from _common import build_orchestrator",
                            "build_orchestrator = None")
    fuente = fuente.replace(
        "from securecenter.projects import PROJECT_SPECS  # noqa: E402",
        "PROJECT_SPECS = []")
    ns = {"__name__": "preparar_para_test"}
    exec(compile(fuente, "preparar.py", "exec"), ns)  # noqa: S102
    return ns


def test_el_token_se_genera_una_sola_vez(tmp_path):
    """Pisar un .env que ya tenía token dejaría al servidor sin poder hablar
    con los agentes que ya lo tienen configurado."""
    prep = _preparar()
    assert prep["_preparar_token"](tmp_path, True) is True
    primero = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "SECUREAGENT_TOKEN=" in primero

    # Segunda corrida: no toca nada y lo dice devolviendo False.
    assert prep["_preparar_token"](tmp_path, False) is False
    assert (tmp_path / ".env").read_text(encoding="utf-8") == primero


def test_el_token_no_pisa_otras_claves_del_env(tmp_path):
    (tmp_path / ".env").write_text("OTRA_COSA=valor\n", encoding="utf-8")
    _preparar()["_preparar_token"](tmp_path, True)
    texto = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "OTRA_COSA=valor" in texto and "SECUREAGENT_TOKEN=" in texto


def test_en_modo_ver_no_escribe_nada(tmp_path):
    """Correrlo sin `--hacelo` tiene que ser seguro: alguien lo va a ejecutar
    para ver qué hace antes de leerlo."""
    prep = _preparar()
    assert prep["_preparar_token"](tmp_path, False) is True
    assert not (tmp_path / ".env").exists()
    assert prep["_preparar_venv"]("X", tmp_path, False) is True
    assert not (tmp_path / "venv").exists()


def test_un_proyecto_que_ya_tiene_venv_no_se_toca(tmp_path):
    prep = _preparar()
    (tmp_path / "venv" / "bin").mkdir(parents=True)
    (tmp_path / "venv" / "bin" / "python").write_text("x")
    assert prep["_preparar_venv"]("X", tmp_path, True) is False


def test_el_mensaje_del_venv_faltante_ofrece_el_atajo(stack_completo, tmp_path):
    """El comando a mano es correcto y sigue estando, pero son dos líneas con
    comillas que hay que copiar bien por cada proyecto."""
    import shutil

    shutil.rmtree(stack_completo / "carpeta-scanner" / "venv")
    o = _orq_completo(stack_completo, tmp_path)
    paso = next(s for s in o.plan_start_one("scanner")
                if "iniciar" in s.label and s.func)
    _ok, detalle = paso.func()
    assert "preparar.py" in detalle and "--hacelo" in detalle
    # Y no se pierde el comando explícito, para quien prefiera hacerlo a mano.
    assert "venv" in detalle


def test_el_atajo_lleva_la_ruta_entera(stack_completo, tmp_path):
    """Decía `python scripts/preparar.py` a secas, y eso solo funciona parado
    en la carpeta de SecureCenter. Quien lee el mensaje tiene la consola
    abierta en OTRO proyecto (es el que acaba de fallar), así que lo copia, lo
    pega, y le dice "can't open file". Un comando que hay que saber desde
    dónde correr no es una instrucción, es una adivinanza."""
    o = _orq_completo(stack_completo, tmp_path)
    comando = o._comando_de_preparar()
    assert "scripts/preparar.py" in comando.replace("\\", "/")
    # Con la ruta absoluta y entre comillas: los proyectos suelen vivir en
    # carpetas con espacios ("Proyectos Github", "OneDrive\Escritorio").
    assert comando.count('"') == 2


# ================== velocidad: qué se hace junto y qué en fila ==================

def test_los_apagados_del_nucleo_van_en_una_tanda(stack_completo, tmp_path):
    """Seis intérpretes de Python arrancando en fila son seis arranques
    sumados; juntos, uno. No dependen entre ellos: el kill por puerto viene
    DESPUÉS de que terminaron todos."""
    o = _orq_completo(stack_completo, tmp_path)
    stops = [s for s in o.plan_stop_core() if "detener" in s.label]
    assert len(stops) >= 6
    assert {s.tanda for s in stops} == {"apagar el núcleo"}


def test_una_tanda_se_agrupa_y_el_resto_queda_en_orden():
    """El agrupado y la ejecución son dos cosas distintas a propósito: así se
    puede probar sin lanzar un solo proceso, y la tanda se corre EN SU LUGAR y
    no antes que todo lo demás."""
    from securecenter.orchestrator import Orchestrator, Step

    pasos = [
        Step("primero", ["a"]),
        Step("junto 1", ["b"], tanda="x"),
        Step("junto 2", ["c"], tanda="x"),
        Step("junto 3", ["d"], tanda="x"),
        Step("despues", ["e"]),
    ]
    unidades = Orchestrator._en_tandas(pasos)
    assert len(unidades) == 3
    assert unidades[0].label == "primero"
    assert [s.label for s in unidades[1]] == ["junto 1", "junto 2", "junto 3"]
    assert unidades[2].label == "despues"


def test_una_tanda_de_uno_no_es_una_tanda():
    """No vale la pena el hilo ni el renglón que anuncia el paralelo."""
    from securecenter.orchestrator import Orchestrator, Step

    unidades = Orchestrator._en_tandas([Step("solo", ["a"], tanda="x")])
    assert not isinstance(unidades[0], list)


def test_los_pasos_de_python_nunca_se_paralelizan():
    """Tocan estado compartido y ya son rápidos. Lo que se corre junto son
    procesos externos, que es donde está el costo."""
    from securecenter.orchestrator import Orchestrator, Step

    pasos = [Step("f1", [], func=lambda: (True, ""), tanda="x"),
             Step("f2", [], func=lambda: (True, ""), tanda="x")]
    assert all(not isinstance(u, list) for u in Orchestrator._en_tandas(pasos))


def test_los_autostart_se_sacan_en_un_solo_paso(stack_completo, tmp_path):
    """Eran cuatro `schtasks /delete` en fila, cada uno un proceso externo de
    entre 200 y 500 ms, y pasaba dos veces: al encender y al apagar."""
    o = _orq_completo(stack_completo, tmp_path)
    pasos = [s for s in o.plan_start_core() if "autostart" in s.label.lower()
             and "propio" in s.label]
    assert len(pasos) == 1
    # Y sigue siendo auditable: se ve qué tareas toca.
    assert "SecureProxyAutostart" in pasos[0].objetivo
    assert "SecureIntelAutostart" in pasos[0].objetivo


def test_si_el_arranque_automatico_falla_igual_se_verifica(stack_completo, tmp_path):
    """Los seis ya arrancaron cuando se llega a ese paso. Si fuera obligatorio
    y fallara (systemd sin bus, permisos), el plan se cortaba ahí y nunca
    llegaba a verificar si el núcleo había quedado arriba: terminabas sin
    saber lo único que importaba, por culpa de lo que menos importaba."""
    o = _orq_completo(stack_completo, tmp_path)
    pasos = o.plan_start_core()
    autostart = next(s for s in pasos if "inicio automático" in s.label)
    assert autostart.optional
    # Y la verificación viene después, así que igual corre.
    assert pasos.index(autostart) < len(pasos) - 1
    assert pasos[-1].label == "verificar que quedó encendido"
