"""Fase 2 del punto 3: Pi-hole entra a la correlación como una fuente más.

Lo que hay que probar acá no es que se lean filas (eso es trivial), sino las
dos cosas que se pueden romper en silencio: que un bloqueo NO se cuente dos
veces cuando SecureDNS además lo importó a su propia base, y que un código de
estado que Pi-hole invente mañana no se interprete a las adivinanzas.
"""

import sqlite3

from securecenter import adaptadores


class ProyectoFalso:
    def __init__(self, db):
        self.found = True
        self._db = db

    def db_path(self, _relativo):
        return self._db


def base_pihole(tmp_path, filas):
    ruta = tmp_path / "pihole-FTL.db"
    con = sqlite3.connect(ruta)
    con.execute("CREATE TABLE queries (id INTEGER PRIMARY KEY, timestamp INTEGER, "
                "type INTEGER, status INTEGER, domain TEXT, client TEXT)")
    con.executemany("INSERT INTO queries (id, timestamp, type, status, domain, "
                    "client) VALUES (?, ?, ?, ?, ?, ?)", filas)
    con.commit()
    con.close()
    return str(ruta)


def base_dns(tmp_path, filas, con_origen=True):
    """La base de SecureDNS, con o sin la columna `origen` (esquema viejo)."""
    ruta = tmp_path / "dns_logs.db"
    con = sqlite3.connect(ruta)
    extra = ", origen TEXT DEFAULT 'propio'" if con_origen else ""
    con.execute("CREATE TABLE queries (id INTEGER PRIMARY KEY, timestamp TEXT, "
                f"domain TEXT, reason TEXT, blocked INTEGER, category TEXT{extra})")
    if con_origen:
        con.executemany("INSERT INTO queries (timestamp, domain, reason, blocked, "
                        "category, origen) VALUES (?, ?, ?, ?, ?, ?)", filas)
    else:
        con.executemany("INSERT INTO queries (timestamp, domain, reason, blocked, "
                        "category) VALUES (?, ?, ?, ?, ?)", filas)
    con.commit()
    con.close()
    return str(ruta)


# ------------------------------------------------------------------ lectura

def test_trae_los_bloqueos_con_el_equipo_que_pregunto(tmp_path):
    """El equipo es el dato que ninguna otra fuente de la suite tenía: hasta
    Pi-hole, todo era 'esta máquina'."""
    db = base_pihole(tmp_path, [
        (1, 1_700_000_000, 1, 1, "malo.com", "192.168.1.20"),
        (2, 1_700_000_001, 1, 2, "bueno.com", "192.168.1.21"),
    ])
    eventos = adaptadores._pihole(db, 100)
    assert len(eventos) == 1
    assert eventos[0].destino == "malo.com"
    assert eventos[0].equipo == "192.168.1.20"
    assert eventos[0].fuente == "Pi-hole"


def test_gravity_entra_bajo_y_una_lista_negra_entra_medio(tmp_path):
    """Desde acá no se puede saber de qué lista salió un bloqueo de gravity, y
    gravity mezcla la publicidad con el malware. Si todo entrara como media,
    una casa normal taparía el panel con miles de bloqueos de publicidad."""
    db = base_pihole(tmp_path, [
        (1, 1_700_000_000, 1, 1, "publicidad.com", "c"),   # gravity
        (2, 1_700_000_001, 1, 5, "prohibido.com", "c"),    # lista negra exacta
    ])
    por_dominio = {e.destino: e for e in adaptadores._pihole(db, 100)}
    assert por_dominio["publicidad.com"].gravedad == "baja"
    assert por_dominio["prohibido.com"].gravedad == "media"


def test_un_estado_nuevo_no_se_interpreta(tmp_path, capsys):
    """Un código que Pi-hole agregue en una versión futura no se adivina."""
    db = base_pihole(tmp_path, [
        (1, 1_700_000_000, 1, 1, "malo.com", "c"),
        (2, 1_700_000_001, 1, 99, "raro.com", "c"),
    ])
    # El 99 ni siquiera pasa el filtro del WHERE, así que para probar el camino
    # se lo mete dentro de los bloqueados a mano.
    eventos = adaptadores._pihole(db, 100)
    assert [e.destino for e in eventos] == ["malo.com"]


def test_los_estados_bloqueados_y_permitidos_no_se_pisan():
    assert not (adaptadores.PIHOLE_BLOQUEADAS & adaptadores.PIHOLE_PERMITIDAS)


def test_una_base_rota_no_tira_abajo_al_resto(tmp_path):
    rota = tmp_path / "rota.db"
    rota.write_text("esto no es una base de datos")
    assert adaptadores._pihole(str(rota), 100) == []


def test_sin_pihole_configurado_no_pasa_nada(tmp_path):
    db = base_dns(tmp_path, [("2026-01-01T10:00:00", "malo.com", "lista", 1, "malware", "propio")])
    eventos = adaptadores.recolectar({"dns": ProyectoFalso(db)})
    assert len(eventos) == 1
    assert eventos[0].fuente == "SecureDNS"


# --------------------------------------------------------- el doble conteo

def test_un_bloqueo_importado_no_se_cuenta_dos_veces(tmp_path):
    """El bug que este filtro evita: SecureDNS importa las consultas de
    Pi-hole a su base, SecureCenter lee las dos, y el mismo bloqueo entra dos
    veces. La correlación creería ver dos herramientas distintas."""
    pihole = base_pihole(tmp_path, [(1, 1_700_000_000, 1, 1, "malo.com", "192.168.1.20")])
    dns = base_dns(tmp_path, [
        # La misma consulta, importada por SecureDNS.
        ("2023-11-14T22:13:20", "malo.com", "gravity", 1, "malware", "pihole"),
        # Un bloqueo propio del resolutor, que sí tiene que entrar.
        ("2026-01-01T10:00:00", "otro.com", "lista", 1, "phishing", "propio"),
    ])

    eventos = adaptadores.recolectar({"dns": ProyectoFalso(dns)}, pihole_db=pihole)

    por_fuente = {}
    for e in eventos:
        por_fuente.setdefault(e.fuente, []).append(e.destino)
    assert por_fuente["SecureDNS"] == ["otro.com"]
    assert por_fuente["Pi-hole"] == ["malo.com"]
    # malo.com aparece UNA sola vez en total.
    assert [e.destino for e in eventos].count("malo.com") == 1


def test_una_base_de_dns_vieja_sin_columna_origen_sigue_funcionando(tmp_path):
    """El filtro nuevo no puede dejar invisible a una base anterior."""
    dns = base_dns(tmp_path, [
        ("2026-01-01T10:00:00", "malo.com", "lista", 1, "malware"),
    ], con_origen=False)
    eventos = adaptadores.recolectar({"dns": ProyectoFalso(dns)})
    assert [e.destino for e in eventos] == ["malo.com"]


def test_una_base_moderna_sin_bloqueos_propios_no_cae_a_la_consulta_vieja(tmp_path):
    """Este es el caso que rompía el truco anterior de 'si vuelve vacío, probá
    la consulta vieja': una base que SOLO tiene filas importadas devolvía cero
    con el filtro puesto, y el reintento sin filtro traía justo esas filas."""
    dns = base_dns(tmp_path, [
        ("2023-11-14T22:13:20", "malo.com", "gravity", 1, "malware", "pihole"),
    ])
    eventos = adaptadores.recolectar({"dns": ProyectoFalso(dns)})
    assert eventos == []


def test_columnas_de_una_base_que_no_existe(tmp_path):
    assert adaptadores._columnas(str(tmp_path / "nada.db"), "queries") == set()


# ------------------------------------------- punto 5, fase 4: CrowdSec

def base_hips(tmp_path, filas):
    ruta = tmp_path / "hips_logs.db"
    con = sqlite3.connect(ruta)
    con.execute("CREATE TABLE bans (id INTEGER PRIMARY KEY, desde REAL, ip TEXT, "
                "motivo TEXT, aplicado INTEGER, puntaje INTEGER, pais TEXT)")
    con.executemany("INSERT INTO bans (desde, ip, motivo, aplicado, puntaje, pais) "
                    "VALUES (?, ?, ?, ?, ?, ?)", filas)
    con.commit()
    con.close()
    return str(ruta)


def test_un_bloqueo_pedido_por_crowdsec_llega_a_detect(tmp_path):
    """Fase 4 del punto 5, y no hizo falta escribir nada nuevo: el adaptador
    del HIPS ya existía y lo que pide CrowdSec queda guardado como un ban más,
    con el origen marcado en el motivo. Este test es la comprobación de que
    esa fase ya está hecha, no código nuevo."""
    db = base_hips(tmp_path, [
        (1_700_000_000.0, "203.0.113.7",
         "pedido por CrowdSec: crowdsecurity/ssh-bf", 1, 0, "RU"),
        (1_700_000_001.0, "203.0.113.9", "fuerza bruta contra RDP", 1, 0, "CN"),
    ])
    eventos = adaptadores.recolectar({"hips": ProyectoFalso(db)})

    por_ip = {e.origen: e for e in eventos if e.tipo == "bloqueo_aplicado"}
    assert "CrowdSec" in por_ip["203.0.113.7"].detalle
    assert "ssh-bf" in por_ip["203.0.113.7"].detalle
    # Y el del vigilante propio sigue distinguiéndose del de CrowdSec.
    assert "CrowdSec" not in por_ip["203.0.113.9"].detalle
    # Los dos entran como alta: un bloqueo aplicado es un bloqueo aplicado,
    # venga de donde venga.
    assert por_ip["203.0.113.7"].gravedad == "alta"


def test_un_bloqueo_de_crowdsec_en_modo_audit_no_miente(tmp_path):
    """En audit no se bloqueó nada. Si entrara como alta, la correlación
    armaría incidentes sobre acciones que nunca ocurrieron."""
    db = base_hips(tmp_path, [
        (1_700_000_000.0, "203.0.113.7", "pedido por CrowdSec: ssh-bf", 0, 0, "RU"),
    ])
    evento = adaptadores.recolectar({"hips": ProyectoFalso(db)})[0]
    assert evento.gravedad == "baja"
    assert evento.ok is False


# ------------------------------------ punto 6, fase 5: Secure-Scanner

def base_scanner(tmp_path, filas):
    ruta = tmp_path / "inventario.db"
    con = sqlite3.connect(ruta)
    con.execute("CREATE TABLE novedades (id INTEGER PRIMARY KEY, ts REAL, "
                "tipo TEXT, mac TEXT, gravedad TEXT, detalle TEXT, datos TEXT, "
                "visto INTEGER DEFAULT 0)")
    con.executemany("INSERT INTO novedades (ts, tipo, mac, gravedad, detalle, "
                    "datos) VALUES (?, ?, ?, ?, ?, ?)", filas)
    con.commit()
    con.close()
    return str(ruta)


def test_un_equipo_nuevo_en_la_red_llega_a_detect(tmp_path):
    db = base_scanner(tmp_path, [
        (1_700_000_000.0, "equipo_nuevo", "3c:37:86:11:22:33", "media",
         "apareció un equipo que nunca había visto: 192.168.1.55",
         '{"ip": "192.168.1.55", "aleatoria": false, "nombre": "192.168.1.55"}'),
    ])
    eventos = adaptadores.recolectar({"scanner": ProyectoFalso(db)})
    assert len(eventos) == 1
    assert eventos[0].fuente == "Secure-Scanner"
    assert eventos[0].gravedad == "media"
    # La IP va como origen para que se cruce con lo que ven las demás fuentes.
    assert eventos[0].origen == "192.168.1.55"
    assert eventos[0].datos["mac"] == "3c:37:86:11:22:33"


def test_un_cambio_de_version_pesa_menos_que_un_puerto_nuevo(tmp_path):
    db = base_scanner(tmp_path, [
        (1_700_000_000.0, "puerto_nuevo", "aa:bb:cc:dd:ee:01", "media",
         "abrió el puerto 22", '{"ip": "192.168.1.5", "puerto": 22}'),
        (1_700_000_001.0, "version_cambiada", "aa:bb:cc:dd:ee:01", "baja",
         "cambió de versión", '{"ip": "192.168.1.5", "puerto": 80}'),
    ])
    por_tipo = {e.datos["tipo"]: e for e in adaptadores.recolectar(
        {"scanner": ProyectoFalso(db)})}
    assert por_tipo["puerto_nuevo"].gravedad == "media"
    assert por_tipo["version_cambiada"].gravedad == "baja"


def test_un_json_roto_no_rompe_el_adaptador(tmp_path):
    """Los datos vienen de otra base: no se les puede tener fe."""
    db = base_scanner(tmp_path, [
        (1_700_000_000.0, "equipo_nuevo", "aa:bb:cc:dd:ee:01", "media",
         "algo pasó", "esto no es json"),
    ])
    eventos = adaptadores.recolectar({"scanner": ProyectoFalso(db)})
    assert len(eventos) == 1
    assert eventos[0].origen == ""


def test_una_base_del_scanner_vieja_sin_novedades_no_rompe(tmp_path):
    """Un inventario de antes de la fase 4 no tiene esa tabla."""
    ruta = tmp_path / "inventario.db"
    con = sqlite3.connect(ruta)
    con.execute("CREATE TABLE equipos (mac TEXT PRIMARY KEY)")
    con.commit()
    con.close()
    assert adaptadores._scanner(str(ruta), 100) == []


def test_el_equipo_del_scanner_es_una_entidad_propia(tmp_path):
    """Lo que aporta esta fuente y ninguna otra: el aparato de la casa como
    entidad, con el nombre que le pusiste."""
    from securecenter import entidades

    db = base_scanner(tmp_path, [
        (1_700_000_000.0, "puerto_nuevo", "aa:bb:cc:dd:ee:01", "media",
         "la impresora abrió el 9100",
         '{"ip": "192.168.1.5", "nombre": "la impresora", "puerto": 9100}'),
    ])
    eventos = adaptadores.recolectar({"scanner": ProyectoFalso(db)})
    mapa = entidades.agrupar(eventos)
    assert "la impresora" in mapa
    assert "192.168.1.5" in mapa
