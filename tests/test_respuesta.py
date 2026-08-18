"""Punto 9, fase 4: que Detect pueda pedirle un bloqueo a SecureHIPS.

Es el primer lugar donde SecureCenter puede cambiar algo del sistema: hasta
acá solo miraba. Por eso lo que más se prueba no es que el pedido salga (eso
son diez líneas) sino todas las veces que tiene que NEGARSE.

La trampa que este módulo existe para evitar: una alerta de Suricata trae dos
IPs, y una de las dos es tuya. En una alerta de comando-y-control saliente el
origen es tu propia PC, y bloquearla deja sin internet al equipo que querías
proteger mientras el implante sigue adentro.
"""

import sys
import time
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))

from securecenter import evento, hips_client, respuesta  # noqa: E402
from securecenter.correlacion import Incidente  # noqa: E402
from securecenter.evento import Evento  # noqa: E402


def _inc(entidad="185.99.1.7", gravedad=evento.ALTA,
         fuentes=("Suricata", "SecureHIPS"), regla="dos_herramientas"):
    evidencias = [Evento(ts=time.time(), fuente=f, tipo=evento.ALERTA_RED,
                         destino=entidad) for f in fuentes]
    return Incidente(regla=regla, titulo="x", entidad=entidad,
                     gravedad=gravedad, confianza=80, evidencias=evidencias)


class ClienteFalso:
    def __init__(self, respuesta_=(True, "SecureHIPS bloqueó la IP")):
        self.respuesta = respuesta_
        self.pedidos = []

    def configurado(self):
        return True

    def por_que_no(self):
        return ""

    def bloquear(self, ip, motivo="", duracion=None):
        self.pedidos.append({"ip": ip, "motivo": motivo, "duracion": duracion})
        return self.respuesta


# ------------------------------------------- qué IP se puede pedir, y cuál no

def test_una_ip_publica_con_dos_fuentes_se_puede_pedir():
    ip, porque = respuesta.candidata(_inc())
    assert ip == "185.99.1.7"
    assert porque == ""


def test_nunca_una_ip_de_tu_propia_red():
    """LA prueba de este módulo.

    En una alerta de C2 saliente la IP privada es TU máquina. Bloquearla en el
    firewall del gateway deja sin internet al equipo infectado, que es el que
    más necesita poder actualizarse, y el implante sigue adentro igual.
    """
    ip, porque = respuesta.candidata(_inc(entidad="192.168.1.44"))
    assert ip == ""
    assert "tu propia red" in porque
    assert "TU máquina" in porque


def test_tampoco_loopback_ni_link_local():
    """127.0.0.1 sería bloquearte a vos mismo. 169.254.x aparece cuando el
    DHCP falla: no es un atacante, es una red rota."""
    for direccion in ("127.0.0.1", "169.254.10.3", "10.0.0.5", "172.16.4.1"):
        assert respuesta.candidata(_inc(entidad=direccion))[0] == ""


def test_un_dominio_no_se_bloquea_en_el_firewall():
    """Y la frase manda a donde sí se corta, en vez de solo decir que no."""
    ip, porque = respuesta.candidata(_inc(entidad="malo.test"))
    assert ip == ""
    assert "SecureDNS" in porque


def test_una_sola_herramienta_no_alcanza():
    """Una sola repitiéndose es la que suele estar equivocada, y bloquear por
    una de esas es cómo se aprende a desconfiar del propio panel."""
    ip, porque = respuesta.candidata(_inc(fuentes=("Suricata",)))
    assert ip == ""
    assert "una sola herramienta" in porque


def test_la_gravedad_baja_no_habilita_el_boton():
    ip, porque = respuesta.candidata(_inc(gravedad=evento.BAJA))
    assert ip == ""
    assert "gravedad" in porque


def test_siempre_hay_un_motivo_cuando_dice_que_no():
    """Un botón que falta sin explicación hace creer que el programa está
    roto. Uno que dice por qué enseña algo."""
    for inc in (_inc(entidad="192.168.1.5"), _inc(entidad="malo.test"),
                _inc(fuentes=("Suricata",)), _inc(gravedad=evento.BAJA), None):
        ip, porque = respuesta.candidata(inc)
        assert ip == "" and porque


def test_una_ipv6_publica_tambien_vale():
    assert respuesta.candidata(_inc(entidad="2001:db8::1"))[0] == ""  # doc: reservada
    assert respuesta.candidata(_inc(entidad="2800:3f0:4001::1"))[0] == "2800:3f0:4001::1"


# --------------------------------------------------------------- el pedido

def test_el_pedido_lleva_la_regla_y_las_fuentes():
    """Dentro de tres semanas, esta frase es todo lo que va a haber en la
    lista de bloqueos de SecureHIPS para entender por qué esa IP está ahí.
    "bloqueo manual" no sirve."""
    cliente = ClienteFalso()
    ok, _detalle = respuesta.pedir(_inc(), cliente)
    assert ok
    motivo = cliente.pedidos[0]["motivo"]
    assert "dos_herramientas" in motivo
    assert "Suricata" in motivo


def test_el_bloqueo_pedido_a_mano_es_corto():
    """Cuatro horas, bastante menos que la escalera propia de SecureHIPS. Lo
    pidió una persona mirando una pantalla, no un detector que vio cinco
    intentos fallidos. Si la IP es mala de verdad va a volver; si fue un
    error, se cae solo antes de que alguien tenga que acordarse de sacarlo."""
    cliente = ClienteFalso()
    respuesta.pedir(_inc(), cliente)
    assert cliente.pedidos[0]["duracion"] == 4 * 3600


def test_si_no_hay_candidata_no_se_llama_al_hips():
    cliente = ClienteFalso()
    ok, detalle = respuesta.pedir(_inc(entidad="192.168.1.44"), cliente)
    assert not ok
    assert cliente.pedidos == []
    assert "no pedí ningún bloqueo" in detalle


def test_sin_hips_configurado_se_dice_y_no_se_bloquea_por_otro_lado():
    """No hay camino de respaldo. Escribir la regla desde acá sería darle un
    segundo dueño al firewall justo cuando el primero está apagado, que es
    cuando menos se mira. Es el error que se le sacó a SecureProxy."""
    class SinConfigurar:
        def configurado(self):
            return False

        def por_que_no(self):
            return "no tiene token"

    ok, detalle = respuesta.pedir(_inc(), SinConfigurar())
    assert not ok
    assert "token" in detalle
    assert "único que escribe en el firewall" in detalle


def test_la_lista_blanca_del_hips_gana():
    """El caso más valioso: el HIPS contesta que no la bloquea porque está en
    su lista blanca. Se muestra tal cual y no se insiste, porque insistir
    sería saltearse la lista blanca."""
    cliente = ClienteFalso((False, "SecureHIPS no la bloqueó: está en la lista blanca"))
    ok, detalle = respuesta.pedir(_inc(), cliente)
    assert not ok
    assert "lista blanca" in detalle


# ------------------------------------------------------------- el cliente

def test_el_cliente_sin_token_no_intenta_nada():
    cliente = hips_client.ClienteHIPS(url="http://127.0.0.1:8892", token="")
    assert not cliente.configurado()
    ok, detalle = cliente.bloquear("1.2.3.4")
    assert not ok
    assert "SECUREHIPS_API_TOKEN" in detalle


def test_el_cliente_se_arma_del_config_y_del_entorno(monkeypatch):
    from securecenter.config_loader import Config

    monkeypatch.setenv("SECUREHIPS_API_TOKEN", "secreto")
    cliente = hips_client.desde_config(Config())
    assert cliente.configurado()
    assert cliente.url.endswith(":8892")


def test_el_token_no_viaja_en_la_url(monkeypatch):
    """Una URL con el token adentro termina en los logs y en el historial."""
    monkeypatch.setenv("SECUREHIPS_API_TOKEN", "secreto")
    cliente = hips_client.desde_config(None)
    assert "secreto" not in cliente.url


def test_el_pedido_no_sale_por_el_proxy_del_sistema():
    """Cuando el núcleo está prendido, el proxy del sistema es SecureProxy: un
    urlopen normal mandaría este pedido al HIPS pasando por el proxy que
    SecureCenter mismo prendió."""
    import ast

    fuente = (RAIZ / "src" / "securecenter" / "hips_client.py").read_text(encoding="utf-8")
    arbol = ast.parse(fuente)
    llamadas = [n for n in ast.walk(arbol) if isinstance(n, ast.Call)]
    assert any("ProxyHandler" in ast.dump(n) for n in llamadas)
    # Y no se usa urlopen directo, que es el que sí respetaría el proxy.
    assert "urllib.request.urlopen" not in fuente
