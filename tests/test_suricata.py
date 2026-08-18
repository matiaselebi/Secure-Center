"""Punto 9, fases 1 y 2: Suricata mirando, y sus alertas en el modelo común.

Lo que más se prueba acá es lo que puede salir MAL callado: que se detecte el
modo IPS (donde una regla ajena te corta internet), que el contenido de los
paquetes no se filtre a la base, y que un eve.json de cientos de megas no se
lea entero cada vez que alguien abre el panel.
"""

import json
import sys
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))

from securecenter import evento, suricata  # noqa: E402


ALERTA = {
    "timestamp": "2026-08-11T21:03:11.123456+0000",
    "flow_id": 1234567890,
    "event_type": "alert",
    "src_ip": "192.168.1.44", "src_port": 51234,
    "dest_ip": "185.99.1.7", "dest_port": 443,
    "proto": "TCP", "app_proto": "tls",
    "alert": {
        "action": "allowed", "gid": 1, "signature_id": 2027865, "rev": 3,
        "signature": "ET MALWARE Cobalt Strike Beacon Observed",
        "category": "A Network Trojan was detected", "severity": 1,
    },
    "tls": {"sni": "cdn-malo.test", "version": "TLS 1.3"},
}


def _eve(tmp_path, *entradas) -> str:
    archivo = tmp_path / "eve.json"
    archivo.write_text("\n".join(json.dumps(e) for e in entradas) + "\n",
                       encoding="utf-8")
    return str(archivo)


# ------------------------------------------------- fase 1: modo y hardware

def test_nfqueue_es_modo_ips(monkeypatch):
    """El caso que la fase 1 existe para evitar. Con NFQUEUE los paquetes
    pasan POR Suricata, así que una regla del ruleset abierto puede cortarte
    internet, y el que la escribió no sabe qué usás."""
    monkeypatch.setattr(suricata, "_linea_de_comando",
                        lambda: "/usr/bin/suricata -c /etc/suricata/suricata.yaml -q 0")
    cual, porque = suricata.modo()
    assert cual == "ips"
    assert "NFQUEUE" in porque


def test_af_packet_es_solo_deteccion(monkeypatch):
    monkeypatch.setattr(suricata, "_linea_de_comando",
                        lambda: "/usr/bin/suricata -c /etc/suricata/suricata.yaml -i eth0")
    monkeypatch.setattr(suricata, "_copy_mode_del_yaml", lambda _r: "")
    assert suricata.modo()[0] == "ids"


def test_copy_mode_ips_en_el_yaml_tambien_es_ips(tmp_path, monkeypatch):
    """Se puede estar en línea sin NFQUEUE: af-packet con copy-mode: ips
    reenvía los paquetes entre dos interfaces y también puede descartarlos."""
    yaml_ = tmp_path / "suricata.yaml"
    yaml_.write_text(
        "%YAML 1.1\n---\naf-packet:\n  - interface: eth0\n"
        "    copy-mode: ips\n    copy-iface: eth1\n", encoding="utf-8")
    monkeypatch.setattr(suricata, "_linea_de_comando",
                        lambda: "/usr/bin/suricata -i eth0")
    assert suricata.modo(str(yaml_))[0] == "ips"


def test_los_ejemplos_comentados_del_yaml_no_cuentan(tmp_path, monkeypatch):
    """EL error que este test bloquea.

    El suricata.yaml que trae el paquete viene con la sección de NFQUEUE y los
    copy-mode escritos y comentados, como ejemplos. Buscar esas palabras en el
    texto del archivo diría "modo IPS" en una instalación recién hecha que no
    está en modo IPS. Ya me pasó lo mismo con `pgrep -f`, que encontraba el
    propio comando que lo estaba invocando.

    Por eso el YAML se parsea y no se lee como texto: un parser ignora los
    comentarios.
    """
    yaml_ = tmp_path / "suricata.yaml"
    yaml_.write_text(
        "%YAML 1.1\n---\n"
        "# af-packet:\n#   - interface: eth0\n#     copy-mode: ips\n"
        "# nfqueue:\n#   mode: accept\n"
        "af-packet:\n  - interface: eth0\n", encoding="utf-8")
    monkeypatch.setattr(suricata, "_linea_de_comando",
                        lambda: "/usr/bin/suricata -i eth0")
    assert suricata.modo(str(yaml_))[0] == "ids"


def test_si_no_esta_corriendo_no_se_afirma_el_modo(monkeypatch):
    monkeypatch.setattr(suricata, "_linea_de_comando", lambda: "")
    cual, porque = suricata.modo()
    assert cual == "desconocido"
    assert porque


def test_el_modo_ips_sale_como_mal_y_dice_como_salir(monkeypatch):
    monkeypatch.setattr(suricata, "hay_suricata", lambda: True)
    monkeypatch.setattr(suricata, "modo", lambda _y=None: ("ips", "está en NFQUEUE"))
    fila = suricata.revisar_modo()
    assert fila["estado"] == suricata.MAL
    assert "SecureHIPS" in fila["detalle"]
    assert fila["arreglo"]


def test_sin_suricata_sale_una_sola_fila_y_dice_que_es_opcional(monkeypatch):
    """Cuatro renglones grises sobre algo que elegiste no instalar es ruido, y
    el ruido en un diagnóstico es lo que hace que se deje de mirar."""
    monkeypatch.setattr(suricata, "hay_suricata", lambda: False)
    filas = suricata.revisar("")
    assert len(filas) == 1
    assert filas[0]["estado"] == suricata.NA
    assert "opcional" in filas[0]["detalle"]


def test_el_hardware_se_reporta_con_el_numero_de_esta_maquina(monkeypatch):
    """"Solo si el hardware aguanta" se decide con un número, no con una
    impresión."""
    monkeypatch.setattr("securecenter.sistema.snapshot",
                        lambda *_a, **_k: {"disponible": True, "ram_total_gb": 1.0,
                                           "cpu_nucleos": 4})
    fila = suricata.revisar_hardware()
    assert fila["estado"] == suricata.MAL
    assert "1 GB" in fila["detalle"]

    monkeypatch.setattr("securecenter.sistema.snapshot",
                        lambda *_a, **_k: {"disponible": True, "ram_total_gb": 8.0,
                                           "cpu_nucleos": 4})
    assert suricata.revisar_hardware()["estado"] == suricata.OK


def test_sin_psutil_no_se_opina_del_hardware(monkeypatch):
    monkeypatch.setattr("securecenter.sistema.snapshot",
                        lambda *_a, **_k: {"disponible": False})
    assert suricata.revisar_hardware()["estado"] == suricata.NA


def test_un_eve_congelado_es_un_aviso_y_no_un_ok(tmp_path):
    """Congelado no es vacío. Si Suricata dejó de escribir, el panel seguiría
    mostrando las alertas viejas como si fueran el estado de ahora."""
    import os
    import time

    ruta = _eve(tmp_path, ALERTA)
    viejo = time.time() - 8 * 3600
    os.utime(ruta, (viejo, viejo))
    fila = suricata.revisar_salida(ruta)
    assert fila["estado"] == suricata.AVISO
    assert "hora" in fila["detalle"]


def test_un_eve_que_no_existe_es_un_problema(tmp_path):
    fila = suricata.revisar_salida(str(tmp_path / "no-esta.json"))
    assert fila["estado"] == suricata.MAL
    assert fila["arreglo"]


# --------------------------------------------- fase 2: leer y traducir

def test_una_alerta_se_convierte_en_evento(tmp_path):
    e = suricata.eventos(_eve(tmp_path, ALERTA))[0]
    assert e.fuente == "Suricata"
    assert e.tipo == evento.ALERTA_RED
    assert e.origen == "192.168.1.44"
    assert e.destino == "185.99.1.7"
    assert "Cobalt Strike" in e.detalle


def test_se_guardan_las_dos_ips_y_no_una(tmp_path):
    """Suricata dice quién ABRIÓ el flujo, no quién es la víctima. En una
    alerta de C2 saliente el origen es tu propia máquina y el que interesa es
    el destino; en un escaneo entrante es al revés. Con las dos, la
    correlación cruza por la que sirva."""
    e = suricata.eventos(_eve(tmp_path, ALERTA))[0]
    assert set(e.indicadores) >= {"192.168.1.44", "185.99.1.7"}


def test_el_nombre_del_certificado_es_lo_que_cruza_con_el_dns(tmp_path):
    """Una alerta con IP sola se cruza con el HIPS y con Intel. Una que trae
    el SNI se cruza además con SecureDNS y con Pi-hole, y ahí el incidente
    pasa de "una IP rara" a "este nombre, que tu DNS ya había bloqueado"."""
    e = suricata.eventos(_eve(tmp_path, ALERTA))[0]
    assert e.dominio == "cdn-malo.test"
    assert "cdn-malo.test" in e.indicadores


def test_la_severidad_de_suricata_esta_invertida():
    """1 es lo MÁS grave y 3 lo menos: es la convención de Snort que Suricata
    heredó. Confundirla haría que un troyano entre como bajo."""
    assert suricata.gravedad_de({"severity": 1, "category": ""}) == evento.ALTA
    assert suricata.gravedad_de({"severity": 3, "category": ""}) == evento.BAJA


def test_una_categoria_grave_gana_sobre_el_numero():
    assert suricata.gravedad_de(
        {"severity": 3, "category": "A Network Trojan was detected"}) == evento.ALTA


def test_lo_que_no_es_alerta_se_ignora(tmp_path):
    """eve.json trae TODOS los flujos, TODAS las consultas DNS y TODOS los
    handshakes que ve. Eso es un volumen enorme de cosas que la suite ya sabe
    por otro lado."""
    ruta = _eve(tmp_path,
                {"event_type": "flow", "src_ip": "1.1.1.1"},
                {"event_type": "dns", "dns": {"rrname": "algo.com"}},
                ALERTA,
                {"event_type": "tls", "tls": {"sni": "otra.com"}})
    assert len(suricata.eventos(ruta)) == 1


def test_una_linea_rota_no_se_lleva_puesto_al_resto(tmp_path):
    archivo = tmp_path / "eve.json"
    archivo.write_text(
        '{"event_type": "alert", "alert": {"signa\n'
        + json.dumps(ALERTA) + "\n", encoding="utf-8")
    assert len(suricata.eventos(str(archivo))) == 1


def test_una_alerta_sin_firma_no_entra(tmp_path):
    """Sin firma no hay nada que mostrar, y un renglón vacío en la línea de
    tiempo es peor que un renglón menos."""
    rota = dict(ALERTA, alert={"severity": 1, "signature": ""})
    assert suricata.eventos(_eve(tmp_path, rota)) == []


def test_un_archivo_que_no_existe_devuelve_vacio_sin_romper():
    assert suricata.eventos("/no/existe/eve.json") == []
    assert suricata.eventos("") == []


# ------------------------- lo que NUNCA se copia (adelanto de la fase 3)

def test_el_contenido_del_paquete_no_entra_nunca(tmp_path):
    """LA prueba del punto 9: metadata, nunca captura completa.

    Adentro de `payload` va la contraseña que alguien escribió en un
    formulario, el token de sesión de su banco, el contenido de un mail. Que
    eso termine en una base de SQLite que se abre desde un panel web es
    convertir una herramienta de seguridad en el problema.
    """
    con_contenido = dict(
        ALERTA,
        payload="dXNlcj1qb2FjbyZwYXNzPWVsc2VjcmV0bw==",
        payload_printable="user=joaco&pass=elsecreto",
        packet="RQAAVAABAAA...",
        http={"hostname": "sitio.test", "http_request_body": "pass=elsecreto"},
    )
    e = suricata.eventos(_eve(tmp_path, con_contenido))[0]

    entero = json.dumps(e.como_dict())
    assert "elsecreto" not in entero
    for prohibido in suricata.CAMPOS_PROHIBIDOS:
        assert prohibido not in e.datos


def test_los_campos_copiados_son_una_lista_blanca(tmp_path):
    """Con lista negra, el día que Suricata agregue un campo nuevo con
    contenido, entraría solo y nadie se enteraría."""
    inventado = dict(ALERTA, campo_del_futuro_con_contenido="algo sensible")
    e = suricata.eventos(_eve(tmp_path, inventado))[0]
    assert "campo_del_futuro_con_contenido" not in e.datos
    permitidos = set(suricata.CAMPOS_DEL_FLUJO) | set(suricata.CAMPOS_DE_LA_ALERTA)
    assert set(e.datos) <= permitidos | {"dominio"}


# ------------------------------------------------- que no cuelgue la máquina

def test_de_un_eve_gigante_se_lee_solo_la_cola(tmp_path):
    """Un eve.json de un gateway con tráfico real pesa cientos de megas, y el
    panel se repinta cada pocos segundos: leerlo entero cada vez sería colgar
    la máquina para mostrar una tabla."""
    archivo = tmp_path / "eve.json"
    relleno = json.dumps({"event_type": "flow", "relleno": "x" * 400}) + "\n"
    with archivo.open("w", encoding="utf-8") as f:
        for _ in range(20000):        # ~8 MB de ruido
            f.write(relleno)
        f.write(json.dumps(ALERTA) + "\n")

    assert archivo.stat().st_size > 3 * suricata.TOPE_DE_LECTURA
    eventos = suricata.eventos(str(archivo))
    assert len(eventos) == 1


def test_lo_viejo_que_queda_afuera_del_tope_no_aparece(tmp_path):
    """La contracara honesta del test anterior: leer solo la cola significa
    que una alerta vieja enterrada bajo megas de tráfico no se ve. Es la misma
    semántica que tienen todos los otros adaptadores ("los últimos N"), y es
    mejor que una marca de agua, porque el archivo rota y un offset guardado
    después de una rotación apunta a cualquier lado."""
    archivo = tmp_path / "eve.json"
    relleno = json.dumps({"event_type": "flow", "relleno": "x" * 400}) + "\n"
    with archivo.open("w", encoding="utf-8") as f:
        f.write(json.dumps(dict(ALERTA, src_ip="10.0.0.99")) + "\n")
        for _ in range(20000):
            f.write(relleno)

    assert suricata.eventos(str(archivo)) == []


# ---------- fase 3: metadata sí, captura completa nunca (lado Suricata)

def _yaml(tmp_path, texto: str) -> str:
    archivo = tmp_path / "suricata.yaml"
    archivo.write_text("%YAML 1.1\n---\n" + texto, encoding="utf-8")
    return str(archivo)


CONFIG_BUENA = """
outputs:
  - eve-log:
      enabled: yes
      types:
        - alert:
            payload: no
            payload-printable: no
            packet: no
            http-body: no
            http-body-printable: no
            tagged-packets: no
            metadata: yes
        - dns
        - flow
  - pcap-log:
      enabled: no
  - file-store:
      version: 2
      enabled: no
"""


def test_la_config_recomendada_pasa_limpia(tmp_path):
    filas = suricata.revisar_privacidad(_yaml(tmp_path, CONFIG_BUENA))
    assert [f["estado"] for f in filas] == [suricata.OK]


def test_el_fragmento_que_se_reparte_es_el_que_pasa():
    """El documento que se le da a la gente para pegar tiene que pasar la
    misma verificación que corre el diagnóstico. Un ejemplo en la
    documentación que el propio programa marcaría como mal es peor que no
    tener ejemplo."""
    fragmento = RAIZ / "docs" / "suricata-eve-log.yaml"
    assert fragmento.exists()
    filas = suricata.revisar_privacidad(str(fragmento))
    assert [f["estado"] for f in filas] == [suricata.OK]


def test_el_payload_prendido_es_un_problema(tmp_path):
    """Adentro va la contraseña que alguien escribió en un formulario."""
    texto = CONFIG_BUENA.replace("payload: no", "payload: yes")
    fila = next(f for f in suricata.revisar_privacidad(_yaml(tmp_path, texto))
                if f["nombre"] == "Suricata: contenido en eve.json")
    assert fila["estado"] == suricata.MAL
    assert "base64" in fila["detalle"]
    # El arreglo dice la opción exacta, no "revisá la configuración".
    assert "payload" in fila["arreglo"]


def test_se_nombran_todas_las_opciones_prendidas_y_no_la_primera(tmp_path):
    texto = (CONFIG_BUENA.replace("payload: no", "payload: yes")
             .replace("http-body: no", "http-body: yes"))
    fila = next(f for f in suricata.revisar_privacidad(_yaml(tmp_path, texto))
                if f["nombre"] == "Suricata: contenido en eve.json")
    assert "payload" in fila["arreglo"] and "http-body" in fila["arreglo"]


def test_pcap_log_prendido_es_la_captura_completa(tmp_path):
    """Es literalmente lo que el punto 9 dice que no: los paquetes crudos,
    tal cual pasaron, en un archivo en el disco del gateway."""
    texto = CONFIG_BUENA.replace("  - pcap-log:\n      enabled: no",
                                 "  - pcap-log:\n      enabled: yes")
    fila = next(f for f in suricata.revisar_privacidad(_yaml(tmp_path, texto))
                if f["nombre"] == "Suricata: pcap-log")
    assert fila["estado"] == suricata.MAL
    assert "pcap-log" in fila["arreglo"]


def test_file_store_prendido_guarda_los_archivos_que_pasan(tmp_path):
    texto = CONFIG_BUENA.replace("      version: 2\n      enabled: no",
                                 "      version: 2\n      enabled: yes")
    fila = next(f for f in suricata.revisar_privacidad(_yaml(tmp_path, texto))
                if f["nombre"] == "Suricata: file-store")
    assert fila["estado"] == suricata.MAL


def test_los_ejemplos_comentados_no_disparan_falsos_positivos(tmp_path):
    """El mismo error de siempre, ahora del lado de la privacidad: el
    suricata.yaml que trae el paquete viene con pcap-log y payload escritos y
    comentados. Buscarlos como texto marcaría en rojo una instalación limpia."""
    texto = CONFIG_BUENA + "\n#  - pcap-log:\n#      enabled: yes\n#      payload: yes\n"
    assert [f["estado"] for f in suricata.revisar_privacidad(_yaml(tmp_path, texto))] == [suricata.OK]


def test_sin_metadata_es_aviso_y_no_error(tmp_path):
    """La capacidad está, le falta un dato: es un aviso. Sin metadata queda el
    número de regla pelado, sin de qué familia de malware es."""
    texto = CONFIG_BUENA.replace("metadata: yes", "metadata: no")
    fila = next(f for f in suricata.revisar_privacidad(_yaml(tmp_path, texto))
                if f["nombre"] == "Suricata: metadata")
    assert fila["estado"] == suricata.AVISO


def test_un_yaml_ilegible_se_dice_y_no_se_afirma_nada(tmp_path):
    """Sin permiso de lectura no se puede saber, y "no se puede saber" no es
    lo mismo que "está bien"."""
    filas = suricata.revisar_privacidad(str(tmp_path / "no-existe.yaml"))
    assert [f["estado"] for f in filas] == [suricata.AVISO]
    assert "sudo" in filas[0]["arreglo"]


def test_un_eve_log_apagado_se_marca(tmp_path):
    texto = CONFIG_BUENA.replace("  - eve-log:\n      enabled: yes",
                                 "  - eve-log:\n      enabled: no")
    fila = next(f for f in suricata.revisar_privacidad(_yaml(tmp_path, texto))
                if f["nombre"] == "Suricata: eve-log")
    assert fila["estado"] == suricata.MAL


def test_el_filtro_de_lectura_sigue_estando_aunque_la_config_este_bien(tmp_path):
    """Son dos mitades del mismo problema y hacen falta las dos.

    La config buena hace que el dato no se escriba. La lista blanca hace que
    no llegue a un evento aunque alguien cambie la config sin avisar, o aunque
    la distribución traiga otro default.
    """
    con_contenido = dict(ALERTA, payload_printable="pass=elsecreto")
    e = suricata.eventos(_eve(tmp_path, con_contenido))[0]
    assert "elsecreto" not in json.dumps(e.como_dict())
