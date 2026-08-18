"""Punto 10, fase 1: el Debian como router de la casa.

Nada de acá toca la red de la máquina donde corre, y no podría: el módulo no
escribe. Es la decisión del punto ("configuración, no un repo"), y estos tests
la sostienen desde el otro lado, verificando que lo único que hace sea mirar.
"""

import subprocess
import sys
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))

from securecenter import gateway  # noqa: E402


def _salida(codigo=0, texto="", error=""):
    return subprocess.CompletedProcess([], codigo, texto, error)


def _tablas(monkeypatch, texto, codigo=0, error=""):
    monkeypatch.setattr(gateway.platform, "system", lambda: "Linux")
    monkeypatch.setattr("securecenter.procutil.run_quiet",
                        lambda *_a, **_k: _salida(codigo, texto, error))


TABLAS = "table inet securehips\ntable inet gateway\ntable ip nat\n"


# --------------------------------------------- lo único que hace: mirar

def test_este_modulo_no_escribe_nada():
    """El punto 10 dice "configuración, no un repo". Un programa que te
    configura el gateway te obliga a depurar DOS cosas cuando algo se rompe:
    la red, y el programa que la configuró.

    Se mira el código: los `nft` que aparecen tienen que ser de lectura.
    """
    import ast

    fuente = (RAIZ / "src" / "securecenter" / "gateway.py").read_text(encoding="utf-8")
    arbol = ast.parse(fuente)
    verbos = set()
    for nodo in ast.walk(arbol):
        if isinstance(nodo, ast.List):
            partes = [e.value for e in nodo.elts
                      if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if partes and partes[0] == "nft":
                verbos.add(partes[1])
    assert verbos <= {"list"}, f"hay comandos de nft que escriben: {verbos}"


# ------------------------------------------------------- ¿es un router?

def test_si_no_reenvia_sale_una_sola_fila(monkeypatch):
    """La mayoría de las instalaciones no son el router de nadie, y llenarles
    la pantalla de renglones sobre un gateway que no tienen es el ruido que
    hace que se deje de mirar el diagnóstico."""
    monkeypatch.setattr(gateway, "reenvia", lambda: False)
    filas = gateway.revisar()
    assert len(filas) == 1
    assert filas[0]["estado"] == gateway.NA
    assert "no falta nada" in filas[0]["detalle"]


def test_no_poder_leer_no_es_lo_mismo_que_estar_apagado(monkeypatch):
    monkeypatch.setattr(gateway, "reenvia", lambda: None)
    assert gateway.revisar()[0]["estado"] == gateway.NA


# ------------------------------------------------------------- el NAT

def test_reenviando_sin_tabla_de_nat_es_un_problema(monkeypatch):
    """Los paquetes salen con la IP privada del celular como origen y no
    vuelven nunca: el mundo no sabe rutear a 192.168.50.x."""
    fila = gateway.revisar_nat(["securehips"], "")
    assert fila["estado"] == gateway.MAL
    assert "no vuelven nunca" in fila["detalle"]
    assert "nftables-gateway.conf" in fila["arreglo"]


def test_con_la_tabla_cargada_esta_bien():
    assert gateway.revisar_nat(["gateway", "securehips"], "")["estado"] == gateway.OK


def test_sin_permiso_no_se_afirma_que_falta_el_nat():
    """Un diagnóstico que dice "no tenés NAT" porque le faltó permiso manda a
    arreglar algo que no está roto, y eso es peor que no decir nada."""
    fila = gateway.revisar_nat([], "Operation not permitted")
    assert fila["estado"] == gateway.AVISO
    assert "no pude leer" in fila["detalle"]


def test_cero_tablas_se_trata_como_falta_de_permisos(monkeypatch):
    """Cero tablas en una máquina que reenvía es casi siempre permisos: lo que
    toque la red (Docker, libvirt, el propio SecureHIPS) crea una tabla."""
    _tablas(monkeypatch, "")
    tablas, motivo = gateway.listar_tablas()
    assert tablas == []
    assert "permisos" in motivo


def test_se_leen_los_nombres_de_las_tablas(monkeypatch):
    _tablas(monkeypatch, TABLAS)
    tablas, motivo = gateway.listar_tablas()
    assert motivo == ""
    assert set(tablas) == {"securehips", "gateway", "nat"}


def test_un_nft_que_falla_devuelve_el_motivo(monkeypatch):
    _tablas(monkeypatch, "", codigo=1, error="Error: Operation not permitted\n")
    assert gateway.listar_tablas() == ([], "Error: Operation not permitted")


def test_sin_nft_instalado_no_se_rompe(monkeypatch):
    monkeypatch.setattr(gateway.platform, "system", lambda: "Linux")

    def explota(*_a, **_k):
        raise FileNotFoundError("nft")

    monkeypatch.setattr("securecenter.procutil.run_quiet", explota)
    tablas, motivo = gateway.listar_tablas()
    assert tablas == [] and "nft" in motivo


# ---------------------------- EL agujero: los bloqueos y el reenvío

def test_sin_cadena_de_forward_los_bloqueos_no_cubren_la_casa(monkeypatch):
    """EL hallazgo de este punto.

    En un gateway, el tráfico del celular, del televisor y de la consola no
    entra por `input` ni sale por `output`: pasa por `forward`. Sin una cadena
    ahí, el panel dice "12 direcciones bloqueadas" mientras esas 12 siguen
    hablando con toda la casa menos con el servidor.

    Un bloqueo que no bloquea es peor que no tener bloqueo, porque además te
    hace creer que estás cubierto.
    """
    monkeypatch.setattr(gateway, "cadenas_de", lambda _t: (["input", "output"], ""))
    fila = gateway.revisar_bloqueos_en_reenvio(["securehips", "gateway"], "")
    assert fila["estado"] == gateway.MAL
    assert "pasa por al lado" in fila["detalle"]
    assert fila["arreglo"]


def test_con_cadena_de_forward_esta_cubierta(monkeypatch):
    monkeypatch.setattr(gateway, "cadenas_de",
                        lambda _t: (["input", "output", "forward"], ""))
    fila = gateway.revisar_bloqueos_en_reenvio(["securehips", "gateway"], "")
    assert fila["estado"] == gateway.OK


def test_los_hooks_se_leen_de_la_salida_de_nft(monkeypatch):
    salida = (
        "table inet securehips {\n"
        "  chain entrada { type filter hook input priority -10; policy accept; }\n"
        "  chain salida { type filter hook output priority -10; policy accept; }\n"
        "  chain reenvio { type filter hook forward priority -10; policy accept; }\n"
        "}\n")
    _tablas(monkeypatch, salida)
    hooks, motivo = gateway.cadenas_de("securehips")
    assert motivo == ""
    assert set(hooks) == {"input", "output", "forward"}


# --------------------------------------------------- convivencia y v6

def test_las_dos_tablas_conviven_y_se_explica_por_que():
    """nftables evalúa cada tabla por separado. Con iptables esto no se podía:
    había una sola cadena FORWARD y el último que escribía pisaba al
    anterior."""
    fila = gateway.revisar_convivencia(["gateway", "securehips"], "")
    assert fila["estado"] == gateway.OK
    assert "por separado" in fila["detalle"]


def test_sin_securehips_cargado_se_avisa():
    fila = gateway.revisar_convivencia(["gateway"], "")
    assert fila["estado"] == gateway.AVISO
    assert "no se están aplicando" in fila["detalle"]


def test_ipv6_reenviando_es_un_aviso(monkeypatch):
    """Los equipos reciben direcciones públicas y salen SIN pasar por el NAT:
    lo que ves en el panel es la mitad de la historia."""
    monkeypatch.setattr(gateway, "reenvia_v6", lambda: True)
    fila = gateway.revisar_ipv6([])
    assert fila["estado"] == gateway.AVISO
    assert "sin pasar por el NAT" in fila["detalle"]


def test_ipv6_apagado_esta_bien(monkeypatch):
    monkeypatch.setattr(gateway, "reenvia_v6", lambda: False)
    assert gateway.revisar_ipv6([])["estado"] == gateway.OK


def test_el_punto_unico_de_falla_siempre_se_dice():
    """No es una falla y no resta puntaje: es un dato que hay que tener
    escrito ANTES de que pase, porque el que lo vaya a arreglar puede no ser
    el que lo configuró."""
    fila = gateway.revisar_punto_unico()
    assert fila["estado"] == gateway.AVISO
    assert "sin internet" in fila["detalle"]
    assert "plan de salida" in fila["arreglo"]


def test_reenviando_salen_todas_las_filas(monkeypatch):
    monkeypatch.setattr(gateway, "reenvia", lambda: True)
    monkeypatch.setattr(gateway, "reenvia_v6", lambda: False)
    monkeypatch.setattr(gateway, "listar_tablas",
                        lambda: (["gateway", "securehips"], ""))
    monkeypatch.setattr(gateway, "cadenas_de",
                        lambda _t: (["input", "output", "forward"], ""))
    monkeypatch.setattr(gateway, "clientes", lambda *_a, **_k: [
        {"ip": "192.168.50.100", "mac": "aa:bb", "nombre": "celular"}])
    monkeypatch.setattr(gateway, "contadores",
                        lambda: ({"reenviados": 5000, "descartados": 3}, ""))
    filas = gateway.revisar()
    assert len(filas) == 10
    # Todas las fases están representadas.
    nombres = " ".join(f["nombre"] for f in filas)
    for esperado in ("NAT", "equipos conectados", "tráfico reenviado",
                     "plan de salida", "punto único"):
        assert esperado in nombres


# --------------------------------- los archivos que se reparten

def test_los_archivos_de_configuracion_estan():
    """Son el entregable de esta fase: cuatro archivos que se copian, se leen
    enteros en un minuto y se borran para volver atrás."""
    carpeta = RAIZ / "gateway"
    for nombre in ("nftables-gateway.conf", "99-gateway.conf",
                   "10-lan.network", "dnsmasq-gateway.conf"):
        assert (carpeta / nombre).exists(), nombre


def test_la_tabla_del_gateway_no_se_llama_igual_que_la_del_hips():
    """Es todo el mecanismo de la convivencia: si compartieran nombre, cargar
    una borraría la otra."""
    texto = (RAIZ / "gateway" / "nftables-gateway.conf").read_text(encoding="utf-8")
    assert "table inet gateway" in texto
    # Y no define ninguna cadena adentro de la tabla de SecureHIPS.
    assert "table inet securehips" not in texto


def test_la_politica_de_reenvio_es_drop():
    """Con `policy accept`, cualquier red mal configurada que llegue a esta
    máquina sale a internet por acá."""
    texto = (RAIZ / "gateway" / "nftables-gateway.conf").read_text(encoding="utf-8")
    assert "hook forward priority filter; policy drop;" in texto


def test_el_estado_establecido_se_acepta_antes_que_nada():
    """Sin esa línea, las respuestas de internet a un pedido del celular caen
    en el drop y no anda absolutamente nada. Es el error clásico y da un
    síntoma engañoso: el ping puede andar mientras la navegación no."""
    texto = (RAIZ / "gateway" / "nftables-gateway.conf").read_text(encoding="utf-8")
    cuerpo = texto.split("chain forward")[1]
    assert cuerpo.index("ct state established,related accept") < cuerpo.index("iifname $LAN")


def test_el_sysctl_deja_ipv6_apagado():
    """Es una decisión y no un olvido: con v6 prendido los equipos salen sin
    pasar por el NAT y el panel muestra la mitad de la historia."""
    texto = (RAIZ / "gateway" / "99-gateway.conf").read_text(encoding="utf-8")
    assert "net.ipv4.ip_forward = 1" in texto
    assert "net.ipv6.conf.all.forwarding = 0" in texto


def test_cada_archivo_dice_como_revertirse():
    """"Opcional, al final, y reversible". Si el camino de vuelta no está
    escrito al lado del de ida, no existe cuando hace falta."""
    for nombre in ("nftables-gateway.conf", "99-gateway.conf",
                   "10-lan.network", "dnsmasq-gateway.conf"):
        texto = (RAIZ / "gateway" / nombre).read_text(encoding="utf-8")
        assert "revert" in texto.lower() or "sacarlo" in texto.lower(), nombre


def test_el_nftables_que_se_reparte_compila():
    """El archivo que se le da a la gente para pegar tiene que ser válido.

    `nft -c` valida sin aplicar: no toca el firewall de la máquina donde corre
    el test. Un ejemplo de la documentación con un error de sintaxis se
    descubre a las once de la noche con la casa sin internet.
    """
    import shutil
    import subprocess

    if not shutil.which("nft"):
        pytest.skip("nft no está instalado acá")
    archivo = RAIZ / "gateway" / "nftables-gateway.conf"
    salida = subprocess.run(["nft", "-c", "-f", str(archivo)],
                            capture_output=True, text=True, timeout=30)
    assert salida.returncode == 0, salida.stderr


# ================= fase 2: probarlo con UN equipo =================

LEASES = (
    "1786000000 aa:bb:cc:dd:ee:ff 192.168.50.100 celular-mati 01:aa:bb\n"
    # Sin nombre: dnsmasq escribe un asterisco cuando el equipo no se
    # presenta. Pasa seguido con televisores y con equipos que randomizan la
    # MAC, que son justo los que más querés poder identificar.
    "1786000000 11:22:33:44:55:66 192.168.50.101 * *\n"
)


def test_se_leen_los_equipos_del_archivo_de_leases(tmp_path):
    """Se lee el archivo y no se escanea la red a propósito: un escaneo activo
    en la fase donde estás probando si la red anda es meter una variable más."""
    archivo = tmp_path / "dhcp.leases"
    archivo.write_text(LEASES, encoding="utf-8")
    equipos = gateway.clientes([str(archivo)])
    assert [e["ip"] for e in equipos] == ["192.168.50.100", "192.168.50.101"]
    assert equipos[0]["nombre"] == "celular-mati"


def test_un_nombre_vacio_se_lee_como_vacio_y_no_como_asterisco(tmp_path):
    archivo = tmp_path / "dhcp.leases"
    archivo.write_text(LEASES, encoding="utf-8")
    assert gateway.clientes([str(archivo)])[1]["nombre"] == ""


def test_sin_archivo_de_leases_no_se_rompe():
    assert gateway.clientes(["/no/existe/leases"]) == []


def test_un_solo_equipo_es_lo_que_pide_la_fase():
    fila = gateway.revisar_cuantos_equipos(
        [{"ip": "192.168.50.100", "nombre": "celular"}])
    assert fila["estado"] == gateway.OK
    assert "todavía es una prueba" in fila["detalle"]


def test_cuando_ya_es_la_casa_entera_se_avisa():
    """Hay un momento exacto en que deja de ser una prueba sin que nadie lo
    decida: cuando alguien apaga el DHCP del router viejo o enchufa el switch.
    Por eso se cuenta y se dice, en vez de confiar en que te acordaste."""
    equipos = [{"ip": f"192.168.50.{i}", "nombre": ""} for i in range(100, 112)]
    fila = gateway.revisar_cuantos_equipos(equipos)
    assert fila["estado"] == gateway.AVISO
    assert "12 equipos" in fila["detalle"]
    assert "la casa entera" in fila["detalle"]


def test_sin_equipos_se_dice_que_falta_el_de_prueba():
    fila = gateway.revisar_cuantos_equipos([])
    assert fila["estado"] == gateway.AVISO
    assert fila["arreglo"]


# ---------------------------------------- ¿pasa de verdad por acá?

def test_el_contador_en_cero_es_el_fallo_que_parece_exito():
    """Separa "el equipo de prueba navega" de "el equipo de prueba navega POR
    ACÁ". Desde el celular las dos cosas se ven igual, y son completamente
    distintas: en una estás filtrando, en la otra tenés un router configurado
    que no usa nadie."""
    fila = gateway.revisar_trafico({"reenviados": 0, "descartados": 0}, "")
    assert fila["estado"] == gateway.MAL
    assert "NI UN paquete" in fila["detalle"]
    assert "router viejo" in fila["detalle"]


def test_mas_descartes_que_reenvios_apunta_al_error_clasico():
    fila = gateway.revisar_trafico({"reenviados": 10, "descartados": 4000}, "")
    assert fila["estado"] == gateway.AVISO
    assert "established" in fila["arreglo"]


def test_con_trafico_pasando_esta_bien():
    fila = gateway.revisar_trafico({"reenviados": 90000, "descartados": 12}, "")
    assert fila["estado"] == gateway.OK
    assert "90,000" in fila["detalle"]


def test_los_contadores_se_leen_de_nft(monkeypatch):
    salida = (
        "table inet gateway {\n"
        "  counter reenviados {\n    packets 1234 bytes 567890\n  }\n"
        "  counter descartados {\n    packets 7 bytes 420\n  }\n"
        "}\n")
    _tablas(monkeypatch, salida)
    valores, motivo = gateway.contadores()
    assert motivo == ""
    assert valores == {"reenviados": 1234, "descartados": 7}


# --------------- EL fallo silencioso de la fase 2: el DNS por afuera

def _pihole(tmp_path, ips, cuando=None):
    import sqlite3
    import time

    cuando = time.time() if cuando is None else cuando
    db = tmp_path / "pihole-FTL.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE queries (timestamp INTEGER, client TEXT, domain TEXT)")
    for ip in ips:
        con.execute("INSERT INTO queries VALUES (?,?,?)", (cuando, ip, "algo.com"))
    con.commit()
    con.close()
    return str(db)


def test_un_equipo_que_navega_sin_pasar_por_pihole_se_detecta(tmp_path):
    """EL fallo silencioso.

    Un celular puede navegar perfecto a través de este router y no pasar UNA
    consulta por Pi-hole: alcanza con un DNS fijo escrito a mano, o con que el
    navegador tenga DNS-sobre-HTTPS, que viene prendido solo en Chrome y
    Firefox. Desde el equipo no se ve ninguna diferencia: la navegación anda,
    el gateway reenvía, los contadores suben.
    """
    db = _pihole(tmp_path, ["192.168.50.101"])
    equipos = [{"ip": "192.168.50.100"}, {"ip": "192.168.50.101"}]
    fila = gateway.revisar_dns_de_los_equipos(equipos, db)
    assert fila["estado"] == gateway.MAL
    assert "192.168.50.100" in fila["detalle"]
    assert "DNS-sobre-HTTPS" in fila["detalle"]
    assert fila["arreglo"]


def test_si_todos_consultan_por_pihole_esta_bien(tmp_path):
    db = _pihole(tmp_path, ["192.168.50.100"])
    fila = gateway.revisar_dns_de_los_equipos([{"ip": "192.168.50.100"}], db)
    assert fila["estado"] == gateway.OK


def test_las_consultas_viejas_no_cuentan(tmp_path):
    """Que haya consultado hace tres días no dice nada sobre ahora, y esta
    fila existe justamente para contestar sobre ahora."""
    import time

    db = _pihole(tmp_path, ["192.168.50.100"], cuando=time.time() - 3 * 86400)
    fila = gateway.revisar_dns_de_los_equipos([{"ip": "192.168.50.100"}], db)
    assert fila["estado"] == gateway.MAL


def test_sin_pihole_configurado_no_se_opina():
    fila = gateway.revisar_dns_de_los_equipos([{"ip": "1.2.3.4"}], "")
    assert fila["estado"] == gateway.NA


def test_una_base_de_pihole_rota_no_tumba_el_diagnostico(tmp_path):
    rota = tmp_path / "rota.db"
    rota.write_text("esto no es sqlite", encoding="utf-8")
    fila = gateway.revisar_dns_de_los_equipos([{"ip": "1.2.3.4"}], str(rota))
    assert fila["estado"] == gateway.AVISO


# ================= fase 3: el plan de salida, probado =================

def test_sin_simulacro_el_plan_no_cuenta(tmp_path):
    """"Si no lo probaste, no lo tenés". Un plan escrito y nunca corrido es
    una hoja de papel: lo que falla al volver atrás no se ve leyendo."""
    fila = gateway.revisar_plan_de_salida(str(tmp_path / "nunca"))
    assert fila["estado"] == gateway.MAL
    assert "hoja de papel" in fila["detalle"]
    assert "salir-del-gateway.sh" in fila["arreglo"]


def test_un_simulacro_reciente_esta_bien(tmp_path):
    import time

    marca = tmp_path / "marca"
    marca.write_text(f"{time.time()} 2026-08-12T10:00:00\n", encoding="utf-8")
    fila = gateway.revisar_plan_de_salida(str(marca))
    assert fila["estado"] == gateway.OK
    assert "probado el" in fila["detalle"]


def test_un_simulacro_viejo_vuelve_a_avisar(tmp_path):
    """En seis meses cambian las interfaces, cambia el módem del proveedor y
    cambia quién se acuerda."""
    import time

    marca = tmp_path / "marca"
    marca.write_text(f"{time.time() - 400 * 86400}\n", encoding="utf-8")
    fila = gateway.revisar_plan_de_salida(str(marca))
    assert fila["estado"] == gateway.AVISO
    assert "cambian las interfaces" in fila["detalle"]


def test_una_marca_ilegible_es_lo_mismo_que_no_haberlo_probado(tmp_path):
    marca = tmp_path / "marca"
    marca.write_text("cualquier cosa\n", encoding="utf-8")
    assert gateway.revisar_plan_de_salida(str(marca))["estado"] == gateway.MAL


# ------------------------------------------- el script de salida

SALIDA = None


def _script():
    return (RAIZ / "gateway" / "salir-del-gateway.sh").read_text(encoding="utf-8")


def test_el_script_de_salida_es_bash_valido():
    import subprocess

    ruta = RAIZ / "gateway" / "salir-del-gateway.sh"
    assert ruta.exists()
    salida = subprocess.run(["bash", "-n", str(ruta)], capture_output=True,
                            text=True, timeout=30)
    assert salida.returncode == 0, salida.stderr


def test_el_modo_por_defecto_no_toca_nada():
    """Correrlo sin argumentos tiene que ser seguro. Alguien lo va a ejecutar
    para ver qué hace antes de leerlo."""
    import subprocess

    ruta = RAIZ / "gateway" / "salir-del-gateway.sh"
    salida = subprocess.run(["bash", str(ruta)], capture_output=True,
                            text=True, timeout=30)
    assert salida.returncode == 0
    assert "no se toca nada" in salida.stdout
    # Muestra los comandos, marcados como que no se ejecutaron.
    assert "[ver]  nft delete table inet gateway" in salida.stdout


def test_saca_los_cuatro_archivos_de_la_fase_1():
    """Si el camino de vuelta se olvida de uno, el que vuelva atrás queda con
    media configuración puesta, que es peor que las dos enteras."""
    texto = _script()
    for destino in ("/etc/sysctl.d/99-gateway.conf",
                    "/etc/nftables.d/gateway.conf",
                    "/etc/dnsmasq.d/gateway.conf",
                    "/etc/systemd/network/10-lan.network"):
        assert destino in texto, destino


def test_no_toca_la_tabla_de_securehips():
    """Salir del gateway no puede dejar la casa sin firewall de paso."""
    texto = _script()
    assert "delete table inet gateway" in texto
    assert "delete table inet securehips" not in texto


def test_un_paso_que_falla_no_detiene_a_los_siguientes():
    """En un plan de salida, que el `rm` de un archivo falle porque no estaba
    no puede impedir que se borren los otros tres."""
    texto = _script()
    assert "sigo con lo que queda" in texto
    # Y por eso NO se usa `set -e`, que abortaría al primer error.
    assert "set -e" not in texto


def test_avisa_de_no_correrlo_por_ssh():
    """Sacar el gateway te puede cortar tu propia sesión, y ahí quedás sin
    manos justo cuando hace falta."""
    assert "no por SSH" in _script() or "no por ssh" in _script().lower()


def test_un_simulacro_que_no_funciono_no_se_anota():
    """Es literalmente lo que dice la fase 3: si no funcionó, no lo tenés."""
    texto = _script()
    assert "NO se anota el simulacro" in texto


def test_el_simulacro_tambien_vuelve():
    """Un simulacro que te deja afuera no es un simulacro. Salir, comprobar
    que la casa anda, y volver: las tres cosas."""
    texto = _script()
    assert "--volver" in texto
    assert "volver_al_gateway" in texto


def test_la_marca_la_escribe_el_script_y_no_el_panel():
    """Tiene que ser prueba de que el camino de vuelta CORRIÓ, no de que
    alguien apretó un botón que dice "ya lo probé"."""
    assert gateway.RUTA_SIMULACRO.split("/")[-1] in _script()
