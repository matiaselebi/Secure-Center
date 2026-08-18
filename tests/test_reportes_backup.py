"""Fase 5: exportar lo que pasó, y guardar la configuración.

Lo que más se prueba del backup no es que guarde bien, sino que NO guarde los
`.env` y que restaurar no pueda escribir fuera de la carpeta del proyecto.
"""

import json
import sqlite3
import sys
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))

from securecenter import backup, reportes  # noqa: E402
from securecenter.projects import PROJECT_SPECS, ManagedProject  # noqa: E402


def _proyecto(tmp_path, key):
    spec = next(s for s in PROJECT_SPECS if s.key == key)
    carpeta = tmp_path / spec.package
    (carpeta / "src" / spec.package).mkdir(parents=True)
    (carpeta / "config").mkdir()
    (carpeta / "data").mkdir()
    return ManagedProject(spec, carpeta)


def _base_dns(p, cuando, cuantos, prefijo="malo"):
    archivo = p.folder / "data" / "dns_logs.db"
    nueva = not archivo.exists()
    con = sqlite3.connect(str(archivo))
    if nueva:
        con.execute("CREATE TABLE queries (id INTEGER PRIMARY KEY, timestamp TEXT, "
                    "domain TEXT, reason TEXT, blocked INTEGER)")
    con.executemany("INSERT INTO queries (timestamp,domain,reason,blocked) VALUES (?,?,?,1)",
                    [(cuando.isoformat(), f"{prefijo}{i}.com", "lista") for i in range(cuantos)])
    con.commit()
    con.close()


# --------------------------------------------------------------- reportes


def test_se_exporta_lo_de_hoy(tmp_path):
    p = _proyecto(tmp_path, "dns")
    _base_dns(p, datetime.now(timezone.utc), 5)
    filas = reportes.recolectar({"dns": p}, dias=1)
    assert len(filas) == 5
    assert filas[0]["proyecto"] == "SecureDNS"


def test_el_rango_deja_afuera_lo_viejo(tmp_path):
    p = _proyecto(tmp_path, "dns")
    _base_dns(p, datetime.now(timezone.utc), 3, "hoy")
    _base_dns(p, datetime.now(timezone.utc) - timedelta(days=40), 9, "viejo")
    assert len(reportes.recolectar({"dns": p}, dias=7)) == 3
    assert len(reportes.recolectar({"dns": p}, dias=90)) == 12


def test_el_corte_es_medianoche_local_y_no_utc():
    """Con corte UTC, en Buenos Aires «hoy» empezaría a las 9 de la mañana."""
    corte = reportes._desde(1)
    local = datetime.fromtimestamp(corte)
    assert (local.hour, local.minute, local.second) == (0, 0, 0)


def test_una_base_rota_no_impide_exportar_las_otras(tmp_path):
    bueno = _proyecto(tmp_path, "dns")
    _base_dns(bueno, datetime.now(timezone.utc), 4)
    roto = _proyecto(tmp_path, "proxy")
    (roto.folder / "data" / "proxy_logs.db").write_text("no soy sqlite", encoding="utf-8")
    assert len(reportes.recolectar({"dns": bueno, "proxy": roto}, dias=7)) == 4


def test_el_json_trae_resumen_y_eventos(tmp_path):
    p = _proyecto(tmp_path, "dns")
    _base_dns(p, datetime.now(timezone.utc), 6)
    filas = reportes.recolectar({"dns": p}, dias=7)
    datos = json.loads(reportes.a_json(filas, 7).decode("utf-8"))
    assert datos["resumen"]["total"] == 6
    assert datos["resumen"]["por_proyecto"]["SecureDNS"] == 6
    assert len(datos["eventos"]) == 6
    assert datos["rango_dias"] == 7


def test_el_csv_lleva_bom_para_que_excel_no_rompa_los_acentos(tmp_path):
    p = _proyecto(tmp_path, "dns")
    _base_dns(p, datetime.now(timezone.utc), 2)
    crudo = reportes.a_csv(reportes.recolectar({"dns": p}, dias=7))
    assert crudo.startswith(b"\xef\xbb\xbf")
    assert b"fecha_local,proyecto,tipo,detalle,ok,fecha" in crudo


def test_sin_datos_el_csv_igual_trae_encabezados():
    """Un archivo de cero bytes parece un error; uno con encabezados dice
    claramente que no hubo nada en ese rango."""
    crudo = reportes.a_csv([])
    assert b"fecha" in crudo


def test_el_nombre_del_archivo_dice_el_rango():
    nombre = reportes.nombre_de_archivo(30, "csv")
    assert nombre.endswith("-30d.csv") and "securecenter" in nombre


# ---------------------------------------------------------------- backup


def _con_config(tmp_path, key, secreto=True):
    p = _proyecto(tmp_path, key)
    (p.folder / "config" / "config.yaml").write_text("umbral: 5\n", encoding="utf-8")
    (p.folder / "data" / "lista_blanca.txt").write_text("192.168.0.1\n", encoding="utf-8")
    if secreto:
        (p.folder / ".env").write_text("TELEGRAM_BOT_TOKEN=secreto123\n", encoding="utf-8")
    return p


def test_el_backup_guarda_config_y_listas(tmp_path):
    p = _con_config(tmp_path, "dns")
    destino = tmp_path / "b.zip"
    resultado = backup.crear({"dns": p}, destino)
    assert destino.exists() and resultado["total"] == 2
    nombres = backup.contenido(destino)
    assert "dns/config/config.yaml" in nombres
    assert "dns/data/lista_blanca.txt" in nombres


def test_el_env_NUNCA_entra_al_backup(tmp_path):
    """Ahí viven el token de Telegram, la clave de AbuseIPDB y el token del
    HIPS. Un backup con secretos termina en Descargas o en un pendrive."""
    p = _con_config(tmp_path, "dns")
    destino = tmp_path / "b.zip"
    backup.crear({"dns": p}, destino)
    with zipfile.ZipFile(destino) as zf:
        crudo = b"".join(zf.read(n) for n in zf.namelist())
    assert b"secreto123" not in crudo
    assert not any(".env" in n for n in backup.contenido(destino))


def test_el_historial_no_entra_salvo_que_lo_pidas(tmp_path):
    """Es lo más pesado y lo más reemplazable. Un backup de dos giga no se hace."""
    p = _con_config(tmp_path, "dns")
    _base_dns(p, datetime.now(timezone.utc), 3)
    sin = backup.contenido(tmp_path / "sin.zip") if False else None
    backup.crear({"dns": p}, tmp_path / "sin.zip")
    backup.crear({"dns": p}, tmp_path / "con.zip", incluir_historial=True)
    assert not any(n.endswith(".db") for n in backup.contenido(tmp_path / "sin.zip"))
    assert any(n.endswith(".db") for n in backup.contenido(tmp_path / "con.zip"))


def test_el_zip_usa_la_clave_del_proyecto_y_no_el_nombre_de_carpeta(tmp_path):
    """Así un backup hecho donde la carpeta se llama «mi-proxy» se restaura
    donde se llama «secure-proxy»."""
    p = _con_config(tmp_path, "dns")
    backup.crear({"dns": p}, tmp_path / "b.zip")
    assert all(n.startswith("dns/") for n in backup.contenido(tmp_path / "b.zip"))


def test_restaurar_devuelve_la_config_guardada(tmp_path):
    p = _con_config(tmp_path, "dns")
    backup.crear({"dns": p}, tmp_path / "b.zip")
    (p.folder / "config" / "config.yaml").write_text("umbral: 999\n", encoding="utf-8")

    resultado = backup.restaurar({"dns": p}, tmp_path / "b.zip")
    assert resultado["ok"]
    assert "umbral: 5" in (p.folder / "config" / "config.yaml").read_text(encoding="utf-8")


def test_restaurar_guarda_antes_lo_que_va_a_pisar(tmp_path):
    """Sin red de contención, restaurar es la función que se usa una vez y
    arruina una tarde."""
    p = _con_config(tmp_path, "dns")
    backup.crear({"dns": p}, tmp_path / "b.zip")
    (p.folder / "config" / "config.yaml").write_text("umbral: 999\n", encoding="utf-8")

    resultado = backup.restaurar({"dns": p}, tmp_path / "b.zip")
    respaldo = Path(resultado["respaldo"])
    assert respaldo.exists()
    with zipfile.ZipFile(respaldo) as zf:
        assert b"999" in zf.read("dns/config/config.yaml")


def test_restaurar_no_puede_escribir_fuera_de_la_carpeta(tmp_path):
    """Zip slip: un zip armado a mano con «../../algo» adentro."""
    p = _con_config(tmp_path, "dns")
    malicioso = tmp_path / "malo.zip"
    with zipfile.ZipFile(malicioso, "w") as zf:
        zf.writestr("dns/../../../robado.txt", "te robé la máquina")
    resultado = backup.restaurar({"dns": p}, malicioso)
    assert not (tmp_path.parent / "robado.txt").exists()
    assert "salirse" in resultado["detalle"]


def test_restaurar_no_repone_secretos(tmp_path):
    p = _con_config(tmp_path, "dns")
    con_secreto = tmp_path / "malo.zip"
    with zipfile.ZipFile(con_secreto, "w") as zf:
        zf.writestr("dns/.env", "TELEGRAM_BOT_TOKEN=inyectado")
    backup.restaurar({"dns": p}, con_secreto)
    assert "inyectado" not in (p.folder / ".env").read_text(encoding="utf-8")


def test_un_zip_roto_no_toca_nada(tmp_path):
    p = _con_config(tmp_path, "dns")
    roto = tmp_path / "roto.zip"
    roto.write_text("esto no es un zip", encoding="utf-8")
    resultado = backup.restaurar({"dns": p}, roto)
    assert not resultado["ok"] and "zip válido" in resultado["detalle"]
    assert "umbral: 5" in (p.folder / "config" / "config.yaml").read_text(encoding="utf-8")


def test_un_proyecto_que_no_esta_se_ignora_sin_romper(tmp_path):
    p = _con_config(tmp_path, "dns")
    backup.crear({"dns": p}, tmp_path / "b.zip")
    otro = _con_config(tmp_path, "hips")
    resultado = backup.restaurar({"hips": otro}, tmp_path / "b.zip")
    assert "ese proyecto no está acá" in resultado["detalle"]


def test_el_backup_explica_que_los_env_no_estan(tmp_path):
    """Al restaurar en una máquina nueva hay que saber qué falta poner."""
    p = _con_config(tmp_path, "dns")
    backup.crear({"dns": p}, tmp_path / "b.zip")
    with zipfile.ZipFile(tmp_path / "b.zip") as zf:
        texto = zf.read("backup.txt").decode("utf-8")
    assert ".env" in texto and "a mano" in texto


def test_el_csv_trae_la_fecha_legible_ademas_de_la_cruda(tmp_path):
    """Abrir un CSV y encontrarse con «2026-08-09T04:16:49.143628+00:00» en la
    primera columna no le sirve a nadie. Pero la cruda tampoco se saca: es la
    que sirve para ordenar y procesar en otra herramienta."""
    p = _proyecto(tmp_path, "dns")
    _base_dns(p, datetime.now(timezone.utc), 2)
    crudo = reportes.a_csv(reportes.recolectar({"dns": p}, dias=7)).decode("utf-8-sig")
    encabezado = crudo.splitlines()[0]
    assert encabezado.startswith("fecha_local")
    assert "fecha" in encabezado.split(",")[-1]
    assert "/" in crudo.splitlines()[1].split(",")[0]


def test_el_json_tambien_la_trae(tmp_path):
    p = _proyecto(tmp_path, "dns")
    _base_dns(p, datetime.now(timezone.utc), 1)
    datos = json.loads(reportes.a_json(reportes.recolectar({"dns": p}, dias=7), 7))
    assert datos["eventos"][0]["fecha_local"]
    assert datos["eventos"][0]["fecha"]


def test_restaurar_no_puede_reemplazar_codigo_del_proyecto(tmp_path):
    """El botón restaura config/listas/bases, no es un escritor arbitrario del repo."""
    p = _con_config(tmp_path, "dns")
    codigo = p.folder / "src" / "securehack" / "pwn.py"
    malicioso = tmp_path / "codigo.zip"
    with zipfile.ZipFile(malicioso, "w") as zf:
        zf.writestr("dns/src/securehack/pwn.py", "print('pwn')")
    resultado = backup.restaurar({"dns": p}, malicioso)
    assert not codigo.exists()
    assert not resultado["ok"]
    assert "no respaldable" in resultado["detalle"]


def test_backup_no_sigue_symlinks_hacia_fuera(tmp_path):
    p = _con_config(tmp_path, "dns")
    secreto = tmp_path / "afuera.txt"
    secreto.write_text("NO-DEBE-ENTRAR", encoding="utf-8")
    enlace = p.folder / "data" / "externo.txt"
    try:
        enlace.symlink_to(secreto)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks no disponibles")

    destino = tmp_path / "symlink.zip"
    backup.crear({"dns": p}, destino)
    with zipfile.ZipFile(destino) as zf:
        crudo = b"".join(zf.read(n) for n in zf.namelist())
    assert b"NO-DEBE-ENTRAR" not in crudo


def test_si_restaura_historial_el_backup_previo_tambien_guarda_historial(tmp_path):
    p = _con_config(tmp_path, "dns")
    db = p.folder / "data" / "historial.db"
    db.write_bytes(b"estado-viejo")
    archivo = tmp_path / "con-db.zip"
    with zipfile.ZipFile(archivo, "w") as zf:
        zf.writestr("dns/data/historial.db", b"estado-nuevo")

    resultado = backup.restaurar({"dns": p}, archivo, ahora=1000)
    assert resultado["ok"] and db.read_bytes() == b"estado-nuevo"
    with zipfile.ZipFile(resultado["respaldo"]) as zf:
        assert zf.read("dns/data/historial.db") == b"estado-viejo"


def test_csv_neutraliza_formulas_pero_json_conserva_el_dato_crudo():
    filas = [{
        "fecha": "2026-08-09T12:00:00+00:00",
        "proyecto": "Secure-Intel",
        "tipo": "feed",
        "detalle": "=HYPERLINK(\"http://malicioso\")",
        "ok": False,
    }]
    csv_texto = reportes.a_csv(filas).decode("utf-8-sig")
    json_datos = json.loads(reportes.a_json(filas, 1))
    assert "'=HYPERLINK" in csv_texto
    assert json_datos["eventos"][0]["detalle"].startswith("=HYPERLINK")
