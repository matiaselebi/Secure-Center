import sqlite3

from securecenter import agentes


def _base(ruta):
    con = sqlite3.connect(ruta)
    con.executescript("""
        CREATE TABLE envios (
            id INTEGER PRIMARY KEY AUTOINCREMENT, agente TEXT, ts_servidor REAL,
            ts_agente REAL, sistema TEXT, de_donde TEXT, recibidos INTEGER,
            nuevos INTEGER, descartados INTEGER);
        CREATE TABLE hallazgos (
            agente TEXT, tipo TEXT, clave TEXT, primera_vez REAL, ultima_vez REAL,
            nombre TEXT, ruta TEXT, usuario TEXT, pid INTEGER, padre TEXT,
            origen TEXT, destino TEXT, puerto INTEGER, detalle TEXT, veces INTEGER);
    """)
    con.executemany(
        "INSERT INTO envios (agente, ts_servidor, ts_agente, sistema, de_donde, "
        "recibidos, nuevos, descartados) VALUES (?, ?, ?, ?, ?, 1, 1, 0)",
        [("pc-activa", 9900, 9900, "Windows 11", "192.168.1.10"),
         ("pc-callada", 1000, 1000, "Linux", "192.168.1.20")])
    con.execute(
        "INSERT INTO hallazgos VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("pc-activa", "proceso", "C:/Windows/app.exe", 9000, 9900, "app.exe",
         "C:/Windows/app.exe", "matia", 10, "", "", "", 0, "--seguro", 1))
    con.commit()
    con.close()


def test_distingue_un_agente_callado_y_lee_solo_su_inventario(tmp_path):
    ruta = tmp_path / "agentes.db"
    _base(ruta)

    datos = agentes.leer(ruta, ahora=10_000, minutos_para_callado=30)

    assert [a["agente"] for a in datos["agentes"] if a["callado"]] == ["pc-callada"]
    assert datos["hallazgos"] == 1
    assert datos["inventario"]["pc-activa"][0]["nombre"] == "app.exe"


def test_una_base_ausente_no_se_crea(tmp_path):
    ruta = tmp_path / "no-existe.db"
    assert agentes.leer(ruta)["agentes"] == []
    assert not ruta.exists()


def test_el_bloque_es_aislado_y_escapa_datos_del_agente(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "config.yaml").write_text(
        "servidor:\n  minutos_para_callado: 30\n", encoding="utf-8")
    ruta = tmp_path / "data" / "agentes.db"
    _base(ruta)
    con = sqlite3.connect(ruta)
    con.execute("UPDATE hallazgos SET detalle = '<script>alert(1)</script>'")
    con.commit()
    con.close()

    class Project:
        found = True
        folder = tmp_path

    cuerpo = agentes.bloque(Project(), ahora=10_000)

    assert "Vista aislada de Secure-Agent" in cuerpo
    assert "pc-activa" in cuerpo and "pc-callada" in cuerpo
    assert "&lt;script&gt;" in cuerpo
    assert "<script>" not in cuerpo
