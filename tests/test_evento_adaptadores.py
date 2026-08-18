"""Secure-Detect, fases 1 a 3: modelo común, adaptadores y entidades.

Lo que más se prueba: que el tiempo se normalice (el bug que ya rompió la
línea de tiempo una vez), que una base rota no tumbe a las otras, y que nada
se invente cuando la fuente no lo sabe.
"""

import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))

from securecenter import adaptadores, entidades, evento  # noqa: E402
from securecenter.evento import Evento  # noqa: E402
from securecenter.projects import PROJECT_SPECS, ManagedProject  # noqa: E402


# ------------------------------------------------------- el modelo común


def test_el_tiempo_se_normaliza_venga_como_venga():
    """Las bases mezclan ISO en texto con epoch en float. Ordenar eso como
    texto ponía todos los eventos del HIPS al final para siempre, porque
    «1785...» ordena antes que «2026-...». Ya pasó una vez."""
    esperado = datetime(2026, 8, 9, 12, 0, tzinfo=timezone.utc).timestamp()
    assert evento.a_epoch("2026-08-09T12:00:00+00:00") == esperado
    assert evento.a_epoch(esperado) == esperado
    assert evento.a_epoch(str(esperado)) == esperado


def test_una_fecha_ilegible_no_rompe_la_lista():
    """Devuelve 0 y ese evento queda último, en vez de tirar todo abajo."""
    assert evento.a_epoch("cualquier cosa") == 0.0
    assert evento.a_epoch(None) == 0.0
    assert evento.a_epoch("") == 0.0


def test_una_fecha_sin_zona_se_asume_utc():
    """Es lo que escriben los proyectos."""
    con_zona = evento.a_epoch("2026-08-09T12:00:00+00:00")
    assert evento.a_epoch("2026-08-09T12:00:00") == con_zona


def test_un_tipo_inventado_no_pasa():
    """El correlacionador arma reglas sobre los tipos: si cada adaptador
    inventara el suyo, las reglas dejarían de aplicar en silencio."""
    e = Evento(ts=1, fuente="X", tipo="loquesea")
    assert e.tipo == evento.PROBLEMA


def test_una_gravedad_inventada_cae_a_media():
    assert Evento(ts=1, fuente="X", tipo=evento.PROBLEMA, gravedad="urgentisima").gravedad == "media"


def test_origen_y_destino_son_campos_y_no_texto():
    """La diferencia entre «203.0.113.7 - fuerza bruta» y origen=«203.0.113.7»
    es que lo segundo se puede cruzar con otra fuente."""
    e = Evento(ts=1, fuente="X", tipo=evento.CONEXION_BLOQUEADA,
               origen="1.2.3.4", destino="MALO.COM")
    assert e.indicadores == ["1.2.3.4", "malo.com"]


def test_lo_que_no_se_sabe_queda_vacio_y_no_se_inventa():
    """Un dato inventado se propaga y termina en un incidente que miente."""
    e = Evento(ts=1, fuente="X", tipo=evento.PROBLEMA)
    assert e.equipo == "" and e.origen == "" and e.destino == ""
    assert e.indicadores == []


def test_el_texto_ajeno_se_acota():
    e = Evento(ts=1, fuente="X", tipo=evento.PROBLEMA, detalle="a" * 5000)
    assert len(e.detalle) <= 300


def test_se_ordena_por_hora_y_despues_por_gravedad():
    a = Evento(ts=100, fuente="X", tipo=evento.PROBLEMA, gravedad="baja")
    b = Evento(ts=100, fuente="X", tipo=evento.PROBLEMA, gravedad="alta")
    c = Evento(ts=200, fuente="X", tipo=evento.PROBLEMA, gravedad="baja")
    assert evento.ordenar([a, b, c]) == [c, b, a]


# --------------------------------------------------------- los adaptadores


def _proyecto(tmp_path, key):
    spec = next(s for s in PROJECT_SPECS if s.key == key)
    carpeta = tmp_path / spec.package
    (carpeta / "src" / spec.package).mkdir(parents=True)
    (carpeta / "data").mkdir()
    return ManagedProject(spec, carpeta)


def _base(p, archivo, ddl, insert, filas):
    con = sqlite3.connect(str(p.folder / "data" / archivo))
    con.execute(ddl)
    con.executemany(insert, filas)
    con.commit()
    con.close()


def test_el_dns_produce_consultas_bloqueadas(tmp_path):
    p = _proyecto(tmp_path, "dns")
    ahora = datetime.now(timezone.utc).isoformat()
    _base(p, "dns_logs.db",
          "CREATE TABLE queries (id INTEGER PRIMARY KEY, timestamp TEXT, domain TEXT, "
          "reason TEXT, blocked INTEGER, category TEXT)",
          "INSERT INTO queries (timestamp,domain,reason,blocked,category) VALUES (?,?,?,1,?)",
          [(ahora, "malo.com", "URLhaus", "malware")])
    eventos = adaptadores.recolectar({"dns": p})
    assert len(eventos) == 1
    assert eventos[0].tipo == evento.CONSULTA_BLOQUEADA
    assert eventos[0].destino == "malo.com"
    assert eventos[0].gravedad == "media"


def test_la_publicidad_pesa_menos_que_el_malware(tmp_path):
    """Si pesaran igual, la pantalla se llena de ruido y lo grave se pierde."""
    p = _proyecto(tmp_path, "dns")
    ahora = datetime.now(timezone.utc).isoformat()
    _base(p, "dns_logs.db",
          "CREATE TABLE queries (id INTEGER PRIMARY KEY, timestamp TEXT, domain TEXT, "
          "reason TEXT, blocked INTEGER, category TEXT)",
          "INSERT INTO queries (timestamp,domain,reason,blocked,category) VALUES (?,?,?,1,?)",
          [(ahora, "ads.com", "lista", "publicidad")])
    assert adaptadores.recolectar({"dns": p})[0].gravedad == "baja"


def test_un_esquema_viejo_sin_categoria_no_queda_invisible(tmp_path):
    """Una base vieja tiene que seguir apareciendo, no desaparecer."""
    p = _proyecto(tmp_path, "dns")
    _base(p, "dns_logs.db",
          "CREATE TABLE queries (id INTEGER PRIMARY KEY, timestamp TEXT, domain TEXT, "
          "reason TEXT, blocked INTEGER)",
          "INSERT INTO queries (timestamp,domain,reason,blocked) VALUES (?,?,?,1)",
          [(datetime.now(timezone.utc).isoformat(), "viejo.com", "lista")])
    assert len(adaptadores.recolectar({"dns": p})) == 1


def test_el_proxy_trae_dominio_y_la_ip_resuelta(tmp_path):
    """Los dos indicadores: el dominio cruza con el DNS, la IP con el HIPS."""
    p = _proyecto(tmp_path, "proxy")
    _base(p, "proxy_logs.db",
          "CREATE TABLE requests (id INTEGER PRIMARY KEY, timestamp TEXT, host TEXT, "
          "reason TEXT, blocked INTEGER, resolved_ip TEXT, process TEXT)",
          "INSERT INTO requests (timestamp,host,reason,blocked,resolved_ip,process) "
          "VALUES (?,?,?,1,?,?)",
          [(datetime.now(timezone.utc).isoformat(), "malo.com", "feed",
            "203.0.113.9", "chrome.exe")])
    e = adaptadores.recolectar({"proxy": p})[0]
    assert e.destino == "203.0.113.9"
    assert e.datos["host"] == "malo.com" and e.datos["proceso"] == "chrome.exe"


def test_un_bloqueo_en_audit_no_pesa_como_uno_aplicado(tmp_path):
    """Un bloqueo en audit NO pasó. Tratarlos igual haría que el
    correlacionador arme incidentes sobre acciones que nunca ocurrieron."""
    p = _proyecto(tmp_path, "hips")
    con = sqlite3.connect(str(p.folder / "data" / "hips_logs.db"))
    con.execute("CREATE TABLE bans (ip TEXT PRIMARY KEY, desde REAL, motivo TEXT, "
                "aplicado INTEGER, puntaje INTEGER, pais TEXT)")
    con.execute("CREATE TABLE intentos (id INTEGER PRIMARY KEY, timestamp REAL, "
                "ip TEXT, usuario TEXT, servicio TEXT)")
    con.executemany("INSERT INTO bans VALUES (?,?,?,?,?,?)", [
        ("1.1.1.1", time.time(), "fuerza bruta", 1, 80, "RU"),
        ("2.2.2.2", time.time(), "fuerza bruta", 0, 80, "CN")])
    con.commit()
    con.close()
    por_ip = {e.origen: e for e in adaptadores.recolectar({"hips": p})
              if e.tipo == evento.BLOQUEO_APLICADO}
    assert por_ip["1.1.1.1"].gravedad == "alta" and por_ip["1.1.1.1"].ok
    assert por_ip["2.2.2.2"].gravedad == "baja" and not por_ip["2.2.2.2"].ok
    assert "audit" in por_ip["2.2.2.2"].detalle


def test_una_base_rota_no_impide_leer_las_otras(tmp_path):
    bueno = _proyecto(tmp_path, "dns")
    _base(bueno, "dns_logs.db",
          "CREATE TABLE queries (id INTEGER PRIMARY KEY, timestamp TEXT, domain TEXT, "
          "reason TEXT, blocked INTEGER)",
          "INSERT INTO queries (timestamp,domain,reason,blocked) VALUES (?,?,?,1)",
          [(datetime.now(timezone.utc).isoformat(), "a.com", "x")])
    roto = _proyecto(tmp_path, "proxy")
    (roto.folder / "data" / "proxy_logs.db").write_text("no soy sqlite", encoding="utf-8")
    assert len(adaptadores.recolectar({"dns": bueno, "proxy": roto})) == 1


def test_sin_proyectos_no_se_rompe_nada():
    assert adaptadores.recolectar({}) == []


def test_agregar_una_fuente_es_una_linea():
    """El registro es la prueba de que el diseño cumple su promesa."""
    claves = {a[0] for a in adaptadores.ADAPTADORES}
    assert {"dns", "proxy", "hips", "vpn", "intel"} <= claves


# ------------------------------------------------------------- entidades


def _ev(**kw):
    base = {"ts": time.time(), "fuente": "X", "tipo": evento.PROBLEMA}
    base.update(kw)
    return Evento(**base)


def test_la_clase_se_detecta_sola():
    assert entidades.clase_de("1.2.3.4") == "ip"
    assert entidades.clase_de("ejemplo.com") == "dominio"
    assert entidades.clase_de("PC-MATIAS") == "equipo"


def test_un_evento_con_dos_indicadores_alimenta_dos_entidades():
    """Es lo que permite seguir la cadena dominio -> IP -> bloqueo."""
    mapa = entidades.agrupar([_ev(origen="1.2.3.4", destino="malo.com")])
    assert set(mapa) == {"1.2.3.4", "malo.com"}


def test_se_puede_preguntar_todo_lo_que_paso_con_una_ip():
    """Hoy eso es abrir cinco tablas en cinco paneles y cruzar a ojo."""
    mapa = entidades.agrupar([
        _ev(fuente="SecureDNS", destino="malo.com"),
        _ev(fuente="SecureProxy", destino="1.2.3.4"),
        _ev(fuente="SecureHIPS", origen="1.2.3.4", gravedad="alta"),
    ])
    ip = entidades.buscar(mapa, "1.2.3.4")
    assert len(ip.eventos) == 2
    assert ip.fuentes == {"SecureProxy", "SecureHIPS"}


def test_la_entidad_es_tan_grave_como_su_peor_evento():
    """Promediar la haría parecer inofensiva por tener ruido alrededor."""
    mapa = entidades.agrupar([
        _ev(origen="1.2.3.4", gravedad="baja"),
        _ev(origen="1.2.3.4", gravedad="alta"),
        _ev(origen="1.2.3.4", gravedad="baja"),
    ])
    assert entidades.buscar(mapa, "1.2.3.4").gravedad == "alta"


def test_se_encuentran_las_vistas_por_varias_fuentes():
    """Es la materia prima de la correlación: lo que ninguna herramienta
    sola puede contestar sobre sí misma."""
    mapa = entidades.agrupar([
        _ev(fuente="SecureDNS", destino="1.2.3.4"),
        _ev(fuente="SecureHIPS", origen="1.2.3.4"),
        _ev(fuente="SecureDNS", destino="5.6.7.8"),
    ])
    cruzadas = [e.valor for e in entidades.en_varias_fuentes(mapa)]
    assert cruzadas == ["1.2.3.4"]


def test_dos_fuentes_pesan_mas_que_diez_eventos_de_una():
    """Diez eventos de una sola fuente puede ser una tontería repetida."""
    eventos = [_ev(fuente="SecureDNS", destino="ruidosa.com") for _ in range(10)]
    eventos += [_ev(fuente="SecureDNS", destino="1.2.3.4"),
                _ev(fuente="SecureHIPS", origen="1.2.3.4")]
    mapa = entidades.agrupar(eventos)
    assert entidades.mas_activas(mapa)[0].valor == "1.2.3.4"


def test_el_equipo_es_una_entidad_aparte():
    """Sin esto no se podría preguntar «qué hizo esta máquina»."""
    mapa = entidades.agrupar([_ev(equipo="PC-MATIAS", destino="malo.com")])
    encontrada = entidades.buscar(mapa, "pc-matias")
    assert encontrada is not None
    assert encontrada.clase == "equipo"
    # Se busca en minúsculas pero se muestra como se llama de verdad.
    assert encontrada.etiqueta == "PC-MATIAS"


def test_buscar_un_equipo_no_depende_de_las_mayusculas():
    """Antes devolvía None y había un test que confirmaba ese comportamiento
    en vez de marcarlo como el bug que era."""
    mapa = entidades.agrupar([_ev(equipo="PC-MATIAS", origen="1.2.3.4")])
    for escrito in ("PC-MATIAS", "pc-matias", "  Pc-Matias  "):
        assert entidades.buscar(mapa, escrito) is not None, escrito


def test_el_proxy_aporta_el_dominio_Y_la_ip(tmp_path):
    """El bug que rompía la correlación entre el DNS y el proxy.

    El adaptador guardaba la IP en `destino` y el dominio en `datos`, que no
    se cruza con nada. SecureDNS creaba la entidad del dominio, SecureProxy
    la de la IP, y la regla que une las dos capas nunca disparaba.
    """
    p = _proyecto(tmp_path, "proxy")
    _base(p, "proxy_logs.db",
          "CREATE TABLE requests (id INTEGER PRIMARY KEY, timestamp TEXT, host TEXT, "
          "reason TEXT, blocked INTEGER, resolved_ip TEXT, process TEXT)",
          "INSERT INTO requests (timestamp,host,reason,blocked,resolved_ip,process) "
          "VALUES (?,?,?,1,?,?)",
          [(datetime.now(timezone.utc).isoformat(), "malo.com", "feed",
            "203.0.113.9", "chrome.exe")])
    e = adaptadores.recolectar({"proxy": p})[0]
    assert e.destino == "203.0.113.9" and e.dominio == "malo.com"
    assert set(e.indicadores) == {"203.0.113.9", "malo.com"}


def test_un_indicador_repetido_no_infla_los_conteos():
    """Si una fuente pusiera el mismo valor en dos campos, la entidad
    recibiría el evento dos veces y todo quedaría contado de más."""
    e = Evento(ts=1, fuente="X", tipo=evento.CONEXION_BLOQUEADA,
               destino="malo.com", dominio="malo.com")
    assert e.indicadores == ["malo.com"]
    assert len(entidades.agrupar([e])["malo.com"].eventos) == 1


def test_un_evento_sin_indicadores_no_crea_entidades():
    assert entidades.agrupar([_ev()]) == {}


def test_el_contexto_trae_todo_junto():
    mapa = entidades.agrupar([_ev(origen="1.2.3.4", fuente="SecureHIPS")])
    ctx = entidades.buscar(mapa, "1.2.3.4").contexto()
    for clave in ("valor", "clase", "eventos", "fuentes", "gravedad",
                  "primera_legible", "ultima_legible"):
        assert clave in ctx, clave


# ---------------- punto 8: el ritmo, lo único que solo puede dar el proxy

def test_el_adaptador_lee_los_ritmos_y_no_los_calcula(tmp_path):
    """La cuenta la hace SecureProxy y la deja escrita en su tabla. Repetirla
    de este lado sería el duplicado que el punto 8 vino a sacar, y encima uno
    peligroso: dos umbrales distintos harían que un panel contradiga al otro
    sin que nadie entienda por qué."""
    db = tmp_path / "proxy_logs.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE ritmos (proceso TEXT, destino TEXT, visto TEXT, "
        "conexiones INTEGER, promedio REAL, coeficiente REAL, bytes INTEGER, "
        "motivo TEXT)")
    conn.execute("INSERT INTO ritmos VALUES (?,?,?,?,?,?,?,?)",
                 ("rundll32.exe", "c2.test", "2026-01-01T00:00:00+00:00",
                  40, 60.0, 0.01, 1234, "40 conexiones cada 60 segundos"))
    conn.commit()
    conn.close()

    eventos = adaptadores._proxy_ritmos(db, 50)
    assert len(eventos) == 1
    e = eventos[0]
    assert e.tipo == evento.RITMO_SOSPECHOSO
    assert e.dominio == "c2.test"
    assert e.datos["proceso"] == "rundll32.exe"
    # MEDIA y no ALTA: lo que lo vuelve grave es que otra fuente coincida en
    # el destino, y de eso se encarga la correlación, no el adaptador.
    assert e.gravedad == evento.MEDIA


def test_sin_tabla_de_ritmos_no_rompe_nada(tmp_path):
    """Una base escrita por una versión anterior del proxy no la tiene."""
    db = tmp_path / "proxy_logs.db"
    sqlite3.connect(db).close()
    assert adaptadores._proxy_ritmos(db, 50) == []


# ---------------- punto 9: Suricata entra por el mismo camino que Pi-hole

def test_suricata_entra_en_recolectar_como_externo(tmp_path, monkeypatch):
    """Misma forma que Pi-hole: un motor del sistema, por ruta absoluta, y
    SecureCenter solo lo lee. Vacío = no está, y no se intenta leer nada."""
    import json

    eve = tmp_path / "eve.json"
    eve.write_text(json.dumps({
        "timestamp": "2026-08-11T21:03:11.000000+0000", "event_type": "alert",
        "src_ip": "192.168.1.44", "dest_ip": "185.99.1.7", "dest_port": 443,
        "alert": {"signature": "ET MALWARE algo", "severity": 1,
                  "category": "A Network Trojan was detected"},
    }) + "\n", encoding="utf-8")

    eventos = adaptadores.recolectar({}, suricata_eve=str(eve))
    assert [e.fuente for e in eventos] == ["Suricata"]
    assert eventos[0].tipo == evento.ALERTA_RED

    # Sin ruta configurada no se lee nada y no se rompe nada.
    assert adaptadores.recolectar({}) == []


def test_un_eve_ilegible_no_tumba_al_resto(tmp_path):
    """Suele ser de root, y SecureCenter no corre como root. Que no se pueda
    leer es un caso normal, no un error que tire abajo las otras fuentes."""
    assert adaptadores.recolectar({}, suricata_eve="/root/no-existe/eve.json") == []
