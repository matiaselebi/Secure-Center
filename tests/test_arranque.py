"""Punto 4, fases 1 y 2: que la suite arranque sola en los dos sistemas.

EL TEST MÁS IMPORTANTE DE ESTE ARCHIVO es el que fija el comando de schtasks
argumento por argumento. Windows funciona hoy; toda esta capa existe para
agregar Linux, y agregar Linux no puede cambiar Windows ni un carácter. Como
el CI corre en Ubuntu, sin ese test nadie se enteraría hasta que alguien
prendiera la suite en su PC.
"""

import platform
from pathlib import Path

import pytest

from securecenter import arranque
from securecenter.config_loader import ArranqueConfig, Config


# ------------------------------------------------------- Windows, sin Windows

def test_el_comando_de_schtasks_no_cambia():
    """Fijado a propósito, argumento por argumento.

    Si alguien "mejora" esto mientras trabaja en la parte de Linux, el test lo
    frena. Cada pedazo está por una razón:
      /sc onlogon -> corre como el usuario, no como SYSTEM (otro perfil).
      /rl limited -> nada arranca elevado solo; el UAC se pide cuando hace falta.
      /f          -> reemplaza la tarea si ya existía, sin preguntar.
    """
    backend = arranque.ArranqueWindows()
    comando = backend.comando_instalar(
        "SecureCenterCoreAutostart",
        [r"C:\proyecto\venv\Scripts\pythonw.exe", r"C:\proyecto\scripts\autostart_core.py"])
    assert comando == [
        "schtasks", "/create", "/tn", "SecureCenterCoreAutostart",
        "/tr", '"C:\\proyecto\\venv\\Scripts\\pythonw.exe" "C:\\proyecto\\scripts\\autostart_core.py"',
        "/sc", "onlogon", "/rl", "limited", "/f",
    ]


def test_las_rutas_van_entre_comillas():
    """`C:\\Program Files\\...` sin comillas se parte en dos argumentos y la
    tarea no arranca. Es el bug clásico que aparece solo en la PC de otro."""
    backend = arranque.ArranqueWindows()
    comando = backend.comando_instalar("X", [r"C:\Program Files\py.exe", r"C:\mis cosas\a.py"])
    objetivo = comando[comando.index("/tr") + 1]
    assert objetivo == '"C:\\Program Files\\py.exe" "C:\\mis cosas\\a.py"'


def test_el_comando_de_borrado_no_cambia():
    assert arranque.ArranqueWindows().comando_quitar("Tarea") == [
        "schtasks", "/delete", "/tn", "Tarea", "/f"]


def test_elegir_en_windows_da_el_backend_de_windows():
    backend = arranque.elegir(sistema="Windows")
    assert isinstance(backend, arranque.ArranqueWindows)
    assert backend.disponible


# ------------------------------------------------------------------- systemd

def systemd(tmp_path, alcance="usuario"):
    backend = arranque.ArranqueSystemd(alcance=alcance, raiz=tmp_path, usuario="mati")
    backend.disponible = True   # no hace falta systemctl para probar el archivo
    return backend


def test_el_nombre_de_la_unidad_se_normaliza(tmp_path):
    b = systemd(tmp_path)
    assert b.nombre_unidad("SecureCenterCoreAutostart") == "secure-center-core-autostart.service"
    assert b.nombre_unidad("SecureDNSAutostart").endswith(".service")


def test_el_nombre_de_la_unidad_no_puede_escaparse_de_la_carpeta(tmp_path):
    """El nombre termina siendo un nombre de archivo: no puede traer barras
    ni `..` o se estaría escribiendo en cualquier lado del disco."""
    b = systemd(tmp_path)
    nombre = b.nombre_unidad("../../etc/cron.d/malo")
    assert "/" not in nombre and ".." not in nombre


def test_la_unidad_tiene_lo_que_tiene_que_tener(tmp_path):
    b = systemd(tmp_path)
    texto = b.contenido("SecureCenterCoreAutostart",
                        ["/proyecto/venv/bin/python", "/proyecto/scripts/autostart_core.py"],
                        cwd="/proyecto")
    assert "ExecStart=" in texto
    assert "WorkingDirectory=/proyecto" in texto
    assert "WantedBy=default.target" in texto      # unidad de usuario
    assert "After=network-online.target" in texto  # sin red no puede bajar feeds
    # El tope de reintentos tiene que estar en [Unit] y no en [Service].
    # Puesto en [Service], systemd 229+ lo IGNORA con un aviso que nadie lee y
    # el tope no existe. Lo destapó `systemd-analyze verify`.
    # Se parte por la cabecera en su propia línea: adentro de los comentarios
    # se nombra a "[Service]" y partir por ahí daría cualquier cosa.
    unit, service = texto.split("\n[Service]\n", 1)
    assert "StartLimitBurst=" in unit
    assert "StartLimitIntervalSec=" in unit
    assert "StartLimit" not in service


def test_la_unidad_de_sistema_va_a_otro_target(tmp_path):
    b = systemd(tmp_path, alcance="sistema")
    texto = b.contenido("X", ["/usr/bin/python3", "/x.py"])
    assert "WantedBy=multi-user.target" in texto


def test_las_rutas_con_espacios_van_entre_comillas(tmp_path):
    """systemd parte ExecStart por espacios: sin comillas, una ruta con
    espacios se convierte en dos argumentos y la unidad no arranca."""
    b = systemd(tmp_path)
    texto = b.contenido("X", ["/home/mati/mis proyectos/venv/bin/python", "/x.py"])
    assert '"/home/mati/mis proyectos/venv/bin/python"' in texto


def test_instalar_escribe_el_archivo(tmp_path, monkeypatch):
    b = systemd(tmp_path)
    corridos = []
    monkeypatch.setattr(b, "_systemctl", lambda *a: corridos.append(a) or (True, ""))

    ok, detalle = b.instalar("SecureCenterCoreAutostart",
                             ["/venv/bin/python", "/scripts/autostart_core.py"], cwd="/proy")

    assert ok, detalle
    unidad = tmp_path / "secure-center-core-autostart.service"
    assert unidad.exists()
    assert ("daemon-reload",) in corridos
    assert any(a[0] == "enable" for a in corridos)


def test_quitar_desactiva_antes_de_borrar(tmp_path, monkeypatch):
    """Borrar el archivo con la unidad todavía habilitada deja un enlace roto
    en .wants/ y systemd se queja en cada arranque de algo que ya no existe."""
    b = systemd(tmp_path)
    unidad = tmp_path / "secure-center-core-autostart.service"
    unidad.parent.mkdir(parents=True, exist_ok=True)
    unidad.write_text("[Unit]\n")
    orden = []
    monkeypatch.setattr(b, "_systemctl", lambda *a: orden.append(a[0]) or (True, ""))

    ok, _ = b.quitar("SecureCenterCoreAutostart")

    assert ok
    assert not unidad.exists()
    assert orden[0] == "disable"


def test_sin_systemctl_no_finge(tmp_path):
    b = arranque.ArranqueSystemd(raiz=tmp_path)
    b.disponible = False
    ok, detalle = b.instalar("X", ["/a", "/b"])
    assert not ok
    assert "systemctl" in detalle


# ---------------------------------------------------------------- el linger

def test_avisa_si_falta_el_linger(tmp_path, monkeypatch):
    """Es LA trampa de systemd --user: la unidad se instala bien, `enable`
    devuelve cero, y en un servidor sin sesión no arranca jamás."""
    monkeypatch.setattr(arranque, "_tiene_linger", lambda usuario: False)
    b = systemd(tmp_path)
    avisos = b.avisos()
    assert avisos
    assert "enable-linger" in avisos[0]
    assert "mati" in avisos[0]


def test_con_linger_no_hay_nada_que_avisar(tmp_path, monkeypatch):
    monkeypatch.setattr(arranque, "_tiene_linger", lambda usuario: True)
    assert systemd(tmp_path).avisos() == []


def test_la_unidad_de_sistema_no_necesita_linger(tmp_path, monkeypatch):
    """Arranca en el boot sin que nadie inicie sesión: el linger no aplica."""
    monkeypatch.setattr(arranque, "_tiene_linger", lambda usuario: False)
    assert systemd(tmp_path, alcance="sistema").avisos() == []


# ------------------------------------------------------- sistema desconocido

def test_un_sistema_que_no_conocemos_lo_dice_en_vez_de_callarse():
    """El bug de origen era devolver lista vacía: todo en verde y nada
    configurado. Un macOS o un Linux sin systemd tienen que dar un mensaje."""
    backend = arranque.elegir(sistema="Darwin")
    assert not backend.disponible
    ok, detalle = backend.instalar("X", ["/a"])
    assert not ok
    assert detalle
    assert backend.avisos()


def test_quitar_en_un_sistema_desconocido_no_es_un_error():
    """Quitar algo que nunca se pudo instalar es un éxito trivial. Fallar acá
    haría que apagar la suite fallara por una función que no existe."""
    ok, _ = arranque.ArranqueNoDisponible().quitar("X")
    assert ok


def test_elegir_respeta_el_alcance_del_config(monkeypatch, tmp_path):
    cfg = Config()
    cfg.arranque = ArranqueConfig(alcance="sistema")
    monkeypatch.setattr(arranque.shutil, "which", lambda n: "/bin/systemctl")
    backend = arranque.elegir(cfg, sistema="Linux")
    assert isinstance(backend, arranque.ArranqueSystemd)
    assert backend.alcance == "sistema"


# ------------------------------------------------------------ el securesuite.sh

RAIZ = Path(__file__).resolve().parent.parent


def test_el_sh_existe():
    assert (RAIZ / "securesuite.sh").exists()


@pytest.mark.skipif(platform.system() == "Windows",
                    reason="Windows no tiene bit de ejecución; git no lo conserva")
def test_el_sh_es_ejecutable():
    """Sin el bit puesto, `./securesuite.sh` contesta 'permission denied' y
    hay que acordarse de llamarlo con `bash`. Se chequea solo donde el bit
    existe: en Windows el modo de archivo no significa lo mismo y este test
    fallaría sin que nada esté mal."""
    assert (RAIZ / "securesuite.sh").stat().st_mode & 0o111


def test_el_sh_tiene_las_mismas_opciones_que_el_bat():
    """No se traduce el .bat: se llaman los mismos scripts de Python. Si el
    menú de Linux dejara de llamar a alguno, sería un menú que promete algo
    que no hace."""
    sh = (RAIZ / "securesuite.sh").read_text(encoding="utf-8")
    for script in ("start_core.py", "stop_all.py", "stop_dashboards.py",
                   "panic.py", "run_dashboard.py", "stop_dashboard.py"):
        assert script in sh, f"al menú de Linux le falta {script}"


def test_el_sh_no_usa_herramientas_de_windows():
    sh = (RAIZ / "securesuite.sh").read_text(encoding="utf-8")
    for prohibido in ("schtasks", "taskkill", "powershell", "reg add"):
        assert prohibido not in sh


def test_el_sh_no_revienta_sin_la_variable_USER():
    """Con `set -u`, nombrar $USER en una sesión de systemd o de cron (donde el
    entorno viene casi vacío) mata el script entero. Apareció corriéndolo."""
    sh = (RAIZ / "securesuite.sh").read_text(encoding="utf-8")
    assert 'USUARIO="${USER:-' in sh
    cuerpo = sh.split('USUARIO="${USER:-', 1)[1]
    assert "$USER\"" not in cuerpo and "$USER " not in cuerpo


def test_el_sh_avisa_de_lo_que_no_aplica():
    """Regla 10: no se muestra un botón muerto ni se omite en silencio.

    Y el texto sale de `capacidades.py`, no escrito adentro del .sh: dos
    textos que dicen lo mismo terminan diciendo cosas distintas.
    """
    sh = (RAIZ / "securesuite.sh").read_text(encoding="utf-8")
    assert "capacidades" in sh
    assert "enable-linger" in sh


# ------------------------------------------- el orquestador usa esta capa

def _orquestador(tmp_path, backend):
    """Un orquestador con un backend de arranque puesto a mano."""
    import securecenter.orchestrator as orch_mod
    from securecenter.config_loader import load_config
    from securecenter.logger_db import LoggerDB

    cfg = load_config(str(tmp_path / "no.yaml"))
    o = orch_mod.Orchestrator(cfg, {}, LoggerDB(str(tmp_path / "c.db")), dry_run=True)
    o._backend_arranque = backend
    return o


class BackendFalso(arranque.Arranque):
    sistema = "Falso"
    disponible = True

    def __init__(self):
        self.instalados = []
        self.quitados = []

    def instalar(self, nombre, argv, cwd=""):
        self.instalados.append((nombre, argv))
        return True, f"instalado {nombre}"

    def quitar(self, nombre):
        self.quitados.append(nombre)
        return True, f"quitado {nombre}"

    def esta_instalado(self, nombre):
        return False


def test_en_linux_el_arranque_automatico_ya_no_se_saltea(tmp_path):
    """El agujero que esto cierra: `if not _is_windows(): return []` hacía que
    encender el núcleo en Linux saliera todo en verde sin dejar NADA
    configurado para el próximo arranque. Ni un error, ni un aviso."""
    backend = BackendFalso()
    pasos = _orquestador(tmp_path, backend)._autostart_steps(True)
    assert pasos, "en Linux tiene que haber un paso de arranque automático"
    assert pasos[0].objetivo == "SecureCenterCoreAutostart"
    ok, detalle = pasos[0].func()
    assert ok, detalle
    assert backend.instalados[0][0] == "SecureCenterCoreAutostart"


def test_apagar_quita_el_arranque_automatico(tmp_path):
    backend = BackendFalso()
    pasos = _orquestador(tmp_path, backend)._autostart_steps(False)
    pasos[0].func()
    assert backend.quitados == ["SecureCenterCoreAutostart"]


def test_si_el_sistema_no_soporta_arranque_se_explica(tmp_path):
    """No se devuelve lista vacía: se devuelve un paso que lo dice. Un plan
    que sale todo bien sin haber configurado nada es la peor forma de fallar."""
    pasos = _orquestador(tmp_path, arranque.ArranqueNoDisponible())._autostart_steps(True)
    assert len(pasos) == 1
    ok, detalle = pasos[0].func()
    assert ok            # no rompe el encendido...
    assert "no sé" in detalle or "no aplica" in detalle.lower()   # ...pero avisa


def test_el_aviso_del_linger_llega_hasta_el_paso(tmp_path):
    """Se instaló bien Y no va a arrancar. Las dos cosas son verdad y hay que
    decir las dos."""
    class ConAviso(BackendFalso):
        def avisos(self):
            return ["falta enable-linger"]

    pasos = _orquestador(tmp_path, ConAviso())._autostart_steps(True)
    ok, detalle = pasos[0].func()
    assert ok
    assert "enable-linger" in detalle
