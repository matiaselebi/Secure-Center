"""Secure-Detect, fases 4 a 6: reglas, incidentes y su estado.

Lo que más se prueba: que NO invente. Una correlación falsa es peor que
ninguna, porque enseña a ignorar la pantalla.
"""

import sqlite3
import sys
import time
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))

from securecenter import correlacion, entidades, evento  # noqa: E402
from securecenter.evento import Evento  # noqa: E402


def _ev(tipo, **kw):
    base = {"ts": time.time(), "fuente": "X", "tipo": tipo}
    base.update(kw)
    return Evento(**base)


def _corr(eventos):
    return correlacion.correlacionar(entidades.agrupar(eventos))


# ------------------------------------ regla: dominio bloqueado y conexión


def test_se_detecta_que_se_insistio_despues_del_bloqueo_de_dns():
    ahora = time.time()
    incidentes = _corr([
        _ev(evento.CONSULTA_BLOQUEADA, fuente="SecureDNS", destino="malo.com", ts=ahora),
        _ev(evento.CONEXION_BLOQUEADA, fuente="SecureProxy", destino="malo.com",
            ts=ahora + 60, datos={"proceso": "powershell.exe"}),
    ])
    assert len(incidentes) >= 1
    uno = next(i for i in incidentes if i.regla == "dominio_y_conexion")
    assert uno.gravedad == "alta"
    assert "powershell.exe" in uno.que_significa


def test_saber_el_proceso_sube_la_confianza():
    """Deja de ser «algo en la máquina» y pasa a ser algo concreto."""
    ahora = time.time()
    con = _corr([
        _ev(evento.CONSULTA_BLOQUEADA, fuente="SecureDNS", destino="a.com", ts=ahora),
        _ev(evento.CONEXION_BLOQUEADA, fuente="SecureProxy", destino="a.com",
            ts=ahora + 10, datos={"proceso": "x.exe"})])
    sin = _corr([
        _ev(evento.CONSULTA_BLOQUEADA, fuente="SecureDNS", destino="b.com", ts=ahora),
        _ev(evento.CONEXION_BLOQUEADA, fuente="SecureProxy", destino="b.com",
            ts=ahora + 10)])
    uno = next(i for i in con if i.regla == "dominio_y_conexion")
    otro = next(i for i in sin if i.regla == "dominio_y_conexion")
    assert uno.confianza > otro.confianza


def test_lo_que_paso_horas_despues_no_se_une():
    """Unirlos daría incidentes inventados, que es lo peor que puede pasar."""
    ahora = time.time()
    incidentes = _corr([
        _ev(evento.CONSULTA_BLOQUEADA, fuente="SecureDNS", destino="malo.com", ts=ahora),
        _ev(evento.CONEXION_BLOQUEADA, fuente="SecureProxy", destino="malo.com",
            ts=ahora + 20000),
    ])
    assert not any(i.regla == "dominio_y_conexion" for i in incidentes)


def test_la_conexion_anterior_al_bloqueo_no_cuenta():
    """Si la conexión fue ANTES, no se insistió: es otra historia."""
    ahora = time.time()
    incidentes = _corr([
        _ev(evento.CONSULTA_BLOQUEADA, fuente="SecureDNS", destino="m.com", ts=ahora),
        _ev(evento.CONEXION_BLOQUEADA, fuente="SecureProxy", destino="m.com",
            ts=ahora - 600),
    ])
    assert not any(i.regla == "dominio_y_conexion" for i in incidentes)


# ---------------------------------------------- regla: dos herramientas


def test_dos_herramientas_sobre_el_mismo_indicador():
    incidentes = _corr([
        _ev(evento.CONEXION_BLOQUEADA, fuente="SecureProxy", destino="1.2.3.4"),
        _ev(evento.BLOQUEO_APLICADO, fuente="SecureHIPS", origen="1.2.3.4", ok=True),
    ])
    uno = next(i for i in incidentes if i.regla == "dos_herramientas")
    assert uno.gravedad == "alta"
    assert "SecureProxy" in uno.que_significa and "SecureHIPS" in uno.que_significa


def test_una_sola_herramienta_repitiendose_no_es_correlacion():
    """Diez eventos de la misma fuente no son dos fuentes coincidiendo."""
    eventos = [_ev(evento.CONSULTA_BLOQUEADA, fuente="SecureDNS", destino="a.com")
               for _ in range(10)]
    assert not any(i.regla == "dos_herramientas" for i in _corr(eventos))


def test_solo_haber_visto_algo_no_alcanza():
    """Si bastara con verla, cualquier IP con tráfico normal calificaría."""
    incidentes = _corr([
        _ev(evento.CAMBIO_ESTADO, fuente="SecureVPN", destino="1.2.3.4"),
        _ev(evento.CAMBIO_ESTADO, fuente="Secure-Intel", destino="1.2.3.4"),
    ])
    assert not any(i.regla == "dos_herramientas" for i in incidentes)


def test_mas_fuentes_mas_confianza_pero_con_techo():
    """La cuarta coincidencia agrega menos que la segunda."""
    dos = _corr([
        _ev(evento.CONEXION_BLOQUEADA, fuente="SecureProxy", destino="9.9.9.9"),
        _ev(evento.BLOQUEO_APLICADO, fuente="SecureHIPS", origen="9.9.9.9")])
    tres = _corr([
        _ev(evento.CONEXION_BLOQUEADA, fuente="SecureProxy", destino="8.8.8.8"),
        _ev(evento.BLOQUEO_APLICADO, fuente="SecureHIPS", origen="8.8.8.8"),
        _ev(evento.CONSULTA_BLOQUEADA, fuente="SecureDNS", destino="8.8.8.8")])
    a = next(i for i in dos if i.regla == "dos_herramientas")
    b = next(i for i in tres if i.regla == "dos_herramientas")
    assert a.confianza < b.confianza <= 95


# ------------------------------------- regla: fuerza bruta más salida


def test_ataque_de_entrada_mas_trafico_de_salida():
    """Si golpean la puerta Y algo de adentro contesta, ya no es un escaneo."""
    eventos = [_ev(evento.INTENTO_ENTRADA, fuente="SecureHIPS", origen="5.5.5.5")
               for _ in range(6)]
    eventos.append(_ev(evento.CONEXION_BLOQUEADA, fuente="SecureProxy", destino="5.5.5.5"))
    uno = next(i for i in _corr(eventos) if i.regla == "fuerza_bruta_y_salida")
    assert uno.gravedad == "alta" and uno.confianza == 90


def test_pocos_intentos_no_son_fuerza_bruta():
    eventos = [_ev(evento.INTENTO_ENTRADA, fuente="SecureHIPS", origen="5.5.5.5")
               for _ in range(2)]
    eventos.append(_ev(evento.CONEXION_BLOQUEADA, fuente="SecureProxy", destino="5.5.5.5"))
    assert not any(i.regla == "fuerza_bruta_y_salida" for i in _corr(eventos))


def test_fuerza_bruta_sola_no_genera_incidente():
    """Eso ya lo cuenta el HIPS: acá el valor es que haya DOS direcciones."""
    eventos = [_ev(evento.INTENTO_ENTRADA, fuente="SecureHIPS", origen="5.5.5.5")
               for _ in range(20)]
    assert not any(i.regla == "fuerza_bruta_y_salida" for i in _corr(eventos))


# ----------------------------------------------------- el conjunto


def test_sin_nada_no_se_inventa_nada():
    """Una correlación falsa enseña a ignorar la pantalla."""
    assert _corr([]) == []
    assert _corr([_ev(evento.CONSULTA_BLOQUEADA, fuente="SecureDNS",
                      destino="normal.com")]) == []


def test_lo_grave_y_lo_confiable_va_primero():
    ahora = time.time()
    eventos = [
        _ev(evento.CONSULTA_BLOQUEADA, fuente="SecureDNS", destino="m.com", ts=ahora),
        _ev(evento.CONEXION_BLOQUEADA, fuente="SecureProxy", destino="m.com", ts=ahora + 5),
    ]
    incidentes = _corr(eventos)
    assert incidentes[0].gravedad == "alta"


def test_una_regla_rota_no_frena_a_las_otras(monkeypatch):
    def explotar(entidad, ventana=0):
        raise RuntimeError("boom")

    monkeypatch.setattr(correlacion, "REGLAS",
                        (("rota", "x", explotar),) + correlacion.REGLAS[1:])
    eventos = [
        _ev(evento.CONEXION_BLOQUEADA, fuente="SecureProxy", destino="1.2.3.4"),
        _ev(evento.BLOQUEO_APLICADO, fuente="SecureHIPS", origen="1.2.3.4"),
    ]
    assert any(i.regla == "dos_herramientas" for i in _corr(eventos))


def test_agregar_una_regla_es_una_linea():
    """El test existe para que sumar una regla sea un cambio deliberado y no
    algo que se cuela. Cuando entró Secure-Agent, esta lista se actualizó a
    mano, que es exactamente lo que se quería que pasara."""
    assert {r[0] for r in correlacion.REGLAS} == {
        "dominio_y_conexion", "dos_herramientas", "fuerza_bruta_y_salida",
        "proceso_y_destino_marcado", "cadena_de_proceso_rara",
        "ritmo_hacia_destino_marcado"}


# ----------------------------------------------------- los incidentes


@pytest.fixture()
def registro(tmp_path):
    return correlacion.RegistroDeIncidentes(sqlite3.connect(str(tmp_path / "c.db")))


def _uno():
    return correlacion.Incidente("regla_x", "Título", "1.2.3.4", "alta", 80,
                                 [_ev(evento.BLOQUEO_APLICADO, origen="1.2.3.4")])


def test_la_huella_no_cambia_si_entra_una_evidencia_mas():
    """Si cambiara, sería un incidente nuevo y perderías el estado que le
    habías puesto."""
    a = _uno()
    b = _uno()
    b.evidencias.append(_ev(evento.INTENTO_ENTRADA, origen="1.2.3.4"))
    assert a.huella == b.huella


def test_el_estado_se_recuerda_entre_vueltas(registro):
    incidente = _uno()
    registro.sincronizar([incidente], ahora=1000)
    assert registro.marcar(incidente.huella, correlacion.VISTO)
    otra_vuelta = _uno()
    registro.sincronizar([otra_vuelta], ahora=2000)
    assert otra_vuelta.estado == correlacion.VISTO


def test_un_estado_inventado_se_rechaza(registro):
    assert not registro.marcar("x", "explotar")


def test_el_contador_cuenta_solo_los_no_vistos(registro):
    incidente = _uno()
    registro.sincronizar([incidente], ahora=1000)
    assert registro.sin_ver([incidente]) == 1
    registro.marcar(incidente.huella, correlacion.VISTO)
    otro = _uno()
    registro.sincronizar([otro], ahora=2000)
    assert registro.sin_ver([otro]) == 0


def test_el_incidente_se_exporta_entero(registro):
    datos = _uno().como_dict()
    for clave in ("huella", "titulo", "entidad", "gravedad", "confianza",
                  "que_significa", "desde_legible", "evidencias"):
        assert clave in datos, clave
    assert datos["evidencias"][0]["fuente"]


# ------------------------------------------- los cuatro bugs corregidos


def test_el_dns_y_el_proxy_ahora_si_se_correlacionan():
    """El bug #1: el proxy guardaba la IP y el dominio quedaba fuera de los
    indicadores, así que la regla nunca veía las dos puntas de la cadena."""
    ahora = time.time()
    incidentes = _corr([
        _ev(evento.CONSULTA_BLOQUEADA, fuente="SecureDNS", destino="malo.com", ts=ahora),
        _ev(evento.CONEXION_BLOQUEADA, fuente="SecureProxy", destino="203.0.113.9",
            dominio="malo.com", ts=ahora + 30, datos={"proceso": "powershell.exe"}),
    ])
    assert any(i.regla == "dominio_y_conexion" for i in incidentes)


def test_dos_herramientas_separadas_por_un_dia_no_coinciden():
    """El bug #2: la regla recibía la ventana y no la usaba. «El proxy la
    bloqueó hoy y el HIPS ayer» no es una coincidencia, son dos cosas."""
    ahora = time.time()
    incidentes = _corr([
        _ev(evento.CONEXION_BLOQUEADA, fuente="SecureProxy", destino="1.2.3.4", ts=ahora),
        _ev(evento.BLOQUEO_APLICADO, fuente="SecureHIPS", origen="1.2.3.4",
            ts=ahora - 86400),
    ])
    assert not any(i.regla == "dos_herramientas" for i in incidentes)


def test_dos_herramientas_juntas_si_coinciden():
    ahora = time.time()
    incidentes = _corr([
        _ev(evento.CONEXION_BLOQUEADA, fuente="SecureProxy", destino="1.2.3.4", ts=ahora),
        _ev(evento.BLOQUEO_APLICADO, fuente="SecureHIPS", origen="1.2.3.4", ts=ahora + 60),
    ])
    assert any(i.regla == "dos_herramientas" for i in incidentes)


def test_la_fuerza_bruta_y_la_salida_tienen_que_pasar_cerca():
    """Un ataque de agosto y una conexión de octubre no son una historia."""
    ahora = time.time()
    eventos = [_ev(evento.INTENTO_ENTRADA, fuente="SecureHIPS", origen="5.5.5.5",
                   ts=ahora + i) for i in range(6)]
    eventos.append(_ev(evento.CONEXION_BLOQUEADA, fuente="SecureProxy",
                       destino="5.5.5.5", ts=ahora - 200000))
    assert not any(i.regla == "fuerza_bruta_y_salida" for i in _corr(eventos))


def test_un_ataque_nuevo_no_hereda_el_cerrado_del_viejo(registro):
    """El bug #3. Un ataque nuevo que llega ya marcado como resuelto es la
    peor forma de fallar que puede tener esto."""
    viejo = correlacion.Incidente(
        "r", "t", "1.2.3.4", "alta", 80,
        [_ev(evento.BLOQUEO_APLICADO, origen="1.2.3.4", ts=1_000_000)])
    registro.sincronizar([viejo], ahora=1_000_000)
    registro.marcar(viejo.huella, correlacion.CERRADO)

    # Dos meses después, la misma IP vuelve.
    nuevo = correlacion.Incidente(
        "r", "t", "1.2.3.4", "alta", 80,
        [_ev(evento.BLOQUEO_APLICADO, origen="1.2.3.4", ts=1_000_000 + 60 * 86400)])
    registro.sincronizar([nuevo], ahora=1_000_000 + 60 * 86400)
    assert nuevo.estado == correlacion.NUEVO
    assert nuevo.episodio == viejo.episodio + 1
    assert nuevo.huella != viejo.huella


def test_lo_que_sigue_pasando_mantiene_su_estado(registro):
    """Lo contrario del anterior: si no hubo silencio, es el mismo episodio y
    el estado que le pusiste tiene que respetarse."""
    uno = correlacion.Incidente(
        "r", "t", "1.2.3.4", "alta", 80,
        [_ev(evento.BLOQUEO_APLICADO, origen="1.2.3.4", ts=1_000_000)])
    registro.sincronizar([uno], ahora=1_000_000)
    registro.marcar(uno.huella, correlacion.VISTO)
    otro = correlacion.Incidente(
        "r", "t", "1.2.3.4", "alta", 80,
        [_ev(evento.BLOQUEO_APLICADO, origen="1.2.3.4", ts=1_000_000 + 600)])
    registro.sincronizar([otro], ahora=1_000_000 + 600)
    assert otro.estado == correlacion.VISTO and otro.episodio == uno.episodio


def test_el_grupo_mas_grande_es_el_que_se_mira():
    """Interesa el momento en que más cosas pasaron juntas, que es donde
    está la historia."""
    ahora = time.time()
    eventos = [_ev(evento.INTENTO_ENTRADA, origen="1.1.1.1", ts=ahora - 100000)]
    eventos += [_ev(evento.INTENTO_ENTRADA, origen="1.1.1.1", ts=ahora + i)
                for i in range(5)]
    grupo = correlacion._mejor_grupo(eventos, 1800)
    assert len(grupo) == 5


def test_timestamps_invalidos_no_se_correlacionan():
    """Dos filas corruptas no pueden parecer simultáneas solo porque ambas dan ts=0."""
    eventos = [
        _ev(evento.CONEXION_BLOQUEADA, fuente="SecureProxy", destino="1.2.3.4", ts=0),
        _ev(evento.BLOQUEO_APLICADO, fuente="SecureHIPS", origen="1.2.3.4", ts=0),
    ]
    assert not any(i.regla == "dos_herramientas" for i in _corr(eventos))


def test_un_cerrado_se_reabre_si_llega_evidencia_nueva_sin_cambiar_episodio(registro):
    viejo = correlacion.Incidente(
        "r", "t", "1.2.3.4", "alta", 80,
        [_ev(evento.BLOQUEO_APLICADO, origen="1.2.3.4", ts=1000)])
    registro.sincronizar([viejo], ahora=1000)
    registro.marcar(viejo.huella, correlacion.CERRADO, ahora=1001)

    activo = correlacion.Incidente(
        "r", "t", "1.2.3.4", "alta", 80,
        [_ev(evento.BLOQUEO_APLICADO, origen="1.2.3.4", ts=1100)])
    registro.sincronizar([activo], ahora=1100)

    assert activo.episodio == viejo.episodio
    assert activo.estado == correlacion.NUEVO


def test_migra_la_tabla_de_incidentes_de_la_version_anterior(tmp_path):
    ruta = tmp_path / "vieja.db"
    con = sqlite3.connect(ruta)
    con.execute("""
        CREATE TABLE incidentes (
            huella TEXT PRIMARY KEY, estado TEXT NOT NULL,
            titulo TEXT NOT NULL DEFAULT '', gravedad TEXT NOT NULL DEFAULT 'media',
            primera REAL NOT NULL, ultima REAL NOT NULL, tocado REAL NOT NULL DEFAULT 0
        )
    """)
    base = correlacion.Incidente(
        "r", "t", "1.2.3.4", "alta", 80,
        [_ev(evento.BLOQUEO_APLICADO, origen="1.2.3.4", ts=1000)]).base
    con.execute(
        "INSERT INTO incidentes VALUES (?,?,?,?,?,?,?)",
        (base, correlacion.VISTO, "viejo", "alta", 1000, 1000, 0),
    )
    con.commit()

    registro_v2 = correlacion.RegistroDeIncidentes(con)
    columnas = {fila[1] for fila in con.execute("PRAGMA table_info(incidentes)")}
    assert {"base", "episodio", "ultimo_evento"} <= columnas

    nuevo = correlacion.Incidente(
        "r", "t", "1.2.3.4", "alta", 80,
        [_ev(evento.BLOQUEO_APLICADO, origen="1.2.3.4", ts=1100)])
    registro_v2.sincronizar([nuevo], ahora=1100)
    assert nuevo.estado == correlacion.VISTO


# ------------------------------------- punto 7, fase 4: lo que ve el agente

def _ev_agente(tipo_agente="conexion", proceso="curl", destino="203.0.113.9",
               equipo="pc-de-mati", cadena="", rara=False, ts=None, cmdline=""):
    return Evento(
        ts=ts if ts is not None else time.time(), fuente="Secure-Agent",
        tipo=evento.CAMBIO_ESTADO if tipo_agente != "proceso" else evento.PROBLEMA,
        gravedad=evento.MEDIA, equipo=equipo, destino=destino,
        detalle=f"{proceso} en {equipo}",
        datos={"tipo_agente": tipo_agente, "proceso": proceso,
               "cadena": cadena, "cadena_rara": rara, "cmdline": cmdline})


def test_el_agente_le_pone_nombre_al_proceso_del_destino_marcado():
    """LA regla del punto 7. El proxy ya decía que esa IP era mala; lo que no
    podía decir, porque desde la red no se ve, es QUÉ programa la abrió."""
    eventos = [
        _ev(evento.CONEXION_BLOQUEADA, fuente="SecureProxy", destino="203.0.113.9"),
        _ev_agente(proceso="powershell.exe"),
    ]
    incidentes = _corr(eventos)
    uno = [i for i in incidentes if i.regla == "proceso_y_destino_marcado"]
    assert uno
    assert "powershell.exe" in uno[0].titulo
    assert "pc-de-mati" in uno[0].que_significa


def test_sin_el_agente_esa_regla_no_dispara():
    """No inventa nada: si nadie puede decir el proceso, no hay incidente
    nuevo. El de "dos herramientas" sigue estando, como antes."""
    eventos = [
        _ev(evento.CONEXION_BLOQUEADA, fuente="SecureProxy", destino="203.0.113.9"),
        _ev(evento.BLOQUEO_APLICADO, fuente="SecureHIPS", origen="203.0.113.9"),
    ]
    assert not [i for i in _corr(eventos) if i.regla == "proceso_y_destino_marcado"]


def test_una_conexion_del_agente_sola_no_es_un_incidente():
    """Tu máquina abre cientos de conexiones legítimas por minuto. Sin que
    otra fuente haya marcado ese destino, esto no dice nada."""
    assert not [i for i in _corr([_ev_agente()])
                if i.regla == "proceso_y_destino_marcado"]


def test_una_cadena_rara_sube_el_incidente_a_alta():
    """Un PowerShell lanzado por un Word conectándose a una IP marcada no
    necesita más evidencia que esa."""
    eventos = [
        _ev(evento.CONEXION_BLOQUEADA, fuente="SecureProxy", destino="203.0.113.9"),
        _ev_agente(proceso="powershell.exe", rara=True,
                   cadena="powershell.exe <- winword.exe"),
    ]
    uno = [i for i in _corr(eventos) if i.regla == "proceso_y_destino_marcado"][0]
    assert uno.gravedad == evento.ALTA
    assert "winword.exe" in uno.que_significa


def test_las_cosas_separadas_en_el_tiempo_no_se_unen():
    """El proxy bloqueó hoy y el agente vio la conexión hace tres días: no es
    la misma historia, y presentarla como una sería inventar."""
    eventos = [
        _ev(evento.CONEXION_BLOQUEADA, fuente="SecureProxy", destino="203.0.113.9"),
        _ev_agente(ts=time.time() - 3 * 86400),
    ]
    assert not [i for i in _corr(eventos) if i.regla == "proceso_y_destino_marcado"]


def test_una_consola_lanzada_por_un_documento_vale_sola():
    """La excepción a la regla de "dos fuentes tienen que coincidir", y está
    justificada: nadie abre PowerShell desde un Word por accidente. Además
    llega ANTES de que salga la conexión."""
    incidentes = _corr([_ev_agente(
        tipo_agente="proceso", proceso="powershell.exe", destino="",
        rara=True, cadena="powershell.exe <- cmd.exe <- winword.exe",
        cmdline="powershell -nop -w hidden -enc SQBFAFgA")])
    uno = [i for i in incidentes if i.regla == "cadena_de_proceso_rara"]
    assert uno
    assert uno[0].gravedad == evento.ALTA
    assert "-enc" in uno[0].que_significa


def test_una_consola_abierta_a_mano_no_levanta_nada():
    """Abrir PowerShell desde el explorador es lo que hacés vos todos los días."""
    assert not [i for i in _corr([_ev_agente(
        tipo_agente="proceso", proceso="powershell.exe", destino="",
        rara=False, cadena="powershell.exe <- explorer.exe")])
        if i.regla == "cadena_de_proceso_rara"]


# ------------------- punto 8: el ritmo, que es lo único propio del proxy

def test_un_ritmo_solo_no_arma_un_incidente():
    """Un cliente de correo revisando cada cinco minutos da exactamente la
    misma firma que un implante. Si esto gritara solo, la pantalla se llenaría
    de programas legítimos y nadie la miraría más."""
    eventos = [_ev(evento.RITMO_SOSPECHOSO, fuente="SecureProxy",
                   dominio="algo.com",
                   datos={"proceso": "thunderbird.exe", "promedio": 300.0,
                          "coeficiente": 0.03})]
    assert not [i for i in _corr(eventos)
                if i.regla == "ritmo_hacia_destino_marcado"]


def test_ritmo_mas_destino_marcado_es_alta():
    """Las dos mitades son débiles solas y fuertes juntas: un programa que le
    habla a un destino ya señalado, y le habla con una regularidad que ninguna
    persona tiene."""
    eventos = [
        _ev(evento.RITMO_SOSPECHOSO, fuente="SecureProxy", dominio="malo.com",
            datos={"proceso": "rundll32.exe", "promedio": 60.0,
                   "coeficiente": 0.02}),
        _ev(evento.CONSULTA_BLOQUEADA, fuente="SecureDNS", dominio="malo.com"),
    ]
    incidente = next(i for i in _corr(eventos)
                     if i.regla == "ritmo_hacia_destino_marcado")
    assert incidente.gravedad == evento.ALTA
    assert "rundll32.exe" in incidente.titulo
    assert "60 segundos" in incidente.que_significa
    # Y explica por qué hacen falta las dos mitades, no solo que coincidieron.
    assert "por separado" in incidente.que_significa


# ------------------- punto 9: las alertas de Suricata entran a las reglas

def test_suricata_cuenta_como_una_herramienta_que_señalo():
    """En modo detección Suricata no bloquea nada, y aun así cuenta.

    La palabra que lo justifica ya estaba escrita en las reglas: dicen
    "señalada", no "bloqueada". Que una herramienta reconozca la firma de un
    troyano adentro del paquete es señalar, y de los más fuertes que hay.
    """
    eventos = [
        _ev(evento.ALERTA_RED, fuente="Suricata", destino="185.99.1.7"),
        _ev(evento.BLOQUEO_APLICADO, fuente="SecureHIPS", origen="185.99.1.7"),
    ]
    assert any(i.regla == "dos_herramientas" for i in _corr(eventos))


def test_suricata_sola_no_alcanza():
    """Una herramienta sola repitiéndose no son dos herramientas
    coincidiendo, por más alertas que tire."""
    eventos = [_ev(evento.ALERTA_RED, fuente="Suricata", destino="185.99.1.7")
               for _ in range(5)]
    assert not [i for i in _corr(eventos) if i.regla == "dos_herramientas"]


def test_una_alerta_de_red_sirve_para_la_regla_del_ritmo():
    """El caso completo del punto 9: Suricata reconoce la firma en el paquete,
    y SecureProxy dice qué programa de tu casa le habla con reloj."""
    eventos = [
        _ev(evento.RITMO_SOSPECHOSO, fuente="SecureProxy", dominio="malo.test",
            datos={"proceso": "rundll32.exe", "promedio": 60.0,
                   "coeficiente": 0.02}),
        _ev(evento.ALERTA_RED, fuente="Suricata", dominio="malo.test"),
    ]
    incidente = next(i for i in _corr(eventos)
                     if i.regla == "ritmo_hacia_destino_marcado")
    assert incidente.gravedad == evento.ALTA
    assert "Suricata" in incidente.que_significa


def test_los_tipos_que_senalan_estan_escritos_una_sola_vez():
    """El test de "no vuelvas a copiarlo".

    Estaba repetido en tres reglas. Cuando entró Suricata eso significó
    acordarse de tocar tres lugares, y olvidarse de uno no rompe ningún test:
    solo hace que una regla vea menos que las otras, para siempre, sin que
    nadie se entere.
    """
    assert set(correlacion.TIPOS_QUE_SENALAN) == {
        evento.CONSULTA_BLOQUEADA, evento.CONEXION_BLOQUEADA,
        evento.BLOQUEO_APLICADO, evento.ALERTA_RED}
