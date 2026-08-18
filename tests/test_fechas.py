"""Las fechas de la línea de tiempo.

El panel mostraba el ISO crudo en UTC ("2026-08-04T01:27:32.698423+00:00") con
un "(UTC)" al lado como disculpa. Eso es ilegible y encima confunde, porque no
es la hora que marca tu reloj: con Buenos Aires en UTC-3, un evento de las
22:27 aparecía como del día siguiente a la 01:27.

Ahora se muestra igual que en SecureProxy, SecureDNS y SecureHIPS:
DD/MM/AAAA HH:MM:SS y en hora local.
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import securecenter.dashboard as dashboard  # noqa: E402
from securecenter.dashboard import formatear_fecha  # noqa: E402
from securecenter.logs import _epoch_a_iso  # noqa: E402


def _con_zona(zona: str, funcion, *args):
    """Corre algo con una zona horaria fija y después la deja como estaba.

    Hace falta porque el resultado depende de la hora local, y la máquina
    donde corre el CI está en UTC mientras que la de Matías está en Buenos
    Aires. Sin fijarla, este test pasaría o fallaría según dónde se corra.
    """
    zonas = {
        "UTC": timezone.utc,
        "America/Argentina/Buenos_Aires": timezone(timedelta(hours=-3)),
    }

    class FechaEnZona(datetime):
        def astimezone(self, tz=None):
            return super().astimezone(zonas[zona])

    with patch.object(dashboard, "datetime", FechaEnZona):
        return funcion(*args)


def test_el_formato_es_el_de_toda_la_suite():
    salida = _con_zona("UTC", formatear_fecha, "2026-08-04T01:27:32.698423+00:00")
    assert salida == "04/08/2026 01:27:32"


def test_se_muestra_en_hora_de_buenos_aires():
    """Lo que hacía que un evento de las 22:27 apareciera como del día
    siguiente. Buenos Aires es UTC-3 todo el año, sin horario de verano."""
    salida = _con_zona(
        "America/Argentina/Buenos_Aires",
        formatear_fecha, "2026-08-04T01:27:32.698423+00:00",
    )
    assert salida == "03/08/2026 22:27:32"


def test_un_timestamp_sin_zona_se_toma_como_utc():
    """Si algún proyecto guardara sin el sufijo de zona, interpretarlo como
    hora local correría todo tres horas."""
    salida = _con_zona(
        "America/Argentina/Buenos_Aires", formatear_fecha, "2026-08-04T01:27:32",
    )
    assert salida == "03/08/2026 22:27:32"


def test_la_fecha_del_hips_tambien_se_convierte():
    """El HIPS guarda epoch; `_epoch_a_iso` lo pasa a ISO UTC y de ahí sale a
    hora local como todos los demás. Los dos pasos tienen que encadenar."""
    iso = _epoch_a_iso(1785864452.0)
    salida = _con_zona("America/Argentina/Buenos_Aires", formatear_fecha, iso)
    assert salida.count("/") == 2
    assert salida.count(":") == 2
    assert len(salida) == len("04/08/2026 01:27:32")


def test_una_fecha_ilegible_se_muestra_tal_cual():
    """Preferible una fecha fea a una fila sin fecha o a una excepción que
    tire abajo la tabla entera."""
    assert formatear_fecha("cualquier cosa") == "cualquier cosa"
    assert formatear_fecha("") == ""
    assert formatear_fecha(None) == "None"


def test_el_orden_sigue_saliendo_del_iso_y_no_del_texto_mostrado():
    """Importante: se formatea al DIBUJAR, no al guardar. Si se ordenara por
    "04/08/2026" como texto, el 4 de agosto de 2026 quedaría antes que el 5 de
    enero, porque compara el día primero."""
    from securecenter.logs import LogRow

    filas = [
        LogRow("2026-01-05T10:00:00+00:00", "SecureDNS", "bloqueo", "a"),
        LogRow("2026-08-04T10:00:00+00:00", "SecureHIPS", "bloqueo", "b"),
    ]
    filas.sort(key=lambda r: r.timestamp, reverse=True)
    assert filas[0].project == "SecureHIPS"
