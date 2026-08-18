"""Dashboard unificado de SecureCenter (puerto 8899).

Mismo estilo oscuro que el resto de la suite. Estructura:
- Barra global arriba: salud de los cinco componentes + botones globales (Encender
  núcleo, Encender VPN, Apagar todo, Pánico).
- Un apartado por proyecto: su estado, sus botones de iniciar/parar ese
  servicio solo, y el link a su propio panel.
- Pestaña "Línea de tiempo": los eventos de todos, mezclados por hora.

Las operaciones largas (aprovisionar la VPN, encender el núcleo) corren en un
hilo aparte, de a una por vez, para no colgar la página. Su salida se ve EN
VIVO en la consola de arriba, línea por línea a medida que ocurre, y al
terminar ese mismo bloque queda verde si salió bien o rojo si falló.

La página se actualiza por SSE y NO recargándose. Antes tenía un
`<meta refresh>` cada 5 segundos, y el problema no era la frecuencia sino que
recargaba todo: volvía a la primera pestaña, reseteaba el scroll y mandaba la
consola al principio justo mientras estabas leyendo un encendido de varios
minutos. Ahora se repintan solo los pedazos que cambiaron. Ver
`_fragmentos` y `_serve_eventos`.
"""

import html as html_lib
import hmac
import json
import secrets
import threading
import time
from http.cookies import SimpleCookie
from datetime import datetime, timezone
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import alertas as mod_alertas
from . import agentes as mod_agentes
from . import diagnostico as mod_diag
from . import automatizaciones as mod_auto
from . import adaptadores as mod_ad
from . import backup as mod_backup
from . import correlacion as mod_corr
from . import entidades as mod_ent
from . import metricas as mod_met
from . import procesos, reportes as mod_rep, resumen, sistema
from .health import ACTIVO, APAGADO, PARCIAL, state_snapshot
from .logger_db import LoggerDB
from .logs import collect_logs
from .orchestrator import Orchestrator
from .projects import PROJECT_SPECS


def _a_epoch(iso: str) -> float:
    """El timestamp como número, para que el filtro de «última hora» compare.

    Si no se puede parsear se devuelve 0: esa fila queda fuera del filtro por
    tiempo en vez de romperlo, que es lo que preferís cuando el dato es raro.
    """
    try:
        momento = datetime.fromisoformat(str(iso))
    except (TypeError, ValueError):
        return 0.0
    if momento.tzinfo is None:
        momento = momento.replace(tzinfo=timezone.utc)
    return momento.timestamp()


def formatear_fecha_ts(ts: float) -> str:
    """Lo mismo pero desde un epoch, que es como guarda el modelo común."""
    from .evento import fecha_legible

    return fecha_legible(ts)


def formatear_fecha(iso: str) -> str:
    """El timestamp guardado, legible y EN HORA LOCAL.

    En la base cada proyecto guarda en UTC y en ISO completo
    ("2026-08-04T01:27:32.698423+00:00") porque así se ordena bien como texto
    y no depende de la zona horaria de la máquina que lo escribió. Pero
    mostrarlo tal cual es ilegible, y encima confunde: no es la hora que marca
    tu reloj. Este panel mostraba el ISO crudo con un "(UTC)" al lado como
    disculpa, que es lo mismo que hacía el de SecureDNS antes de arreglarlo.

    Es la misma función que ya tiene SecureDNS, con el mismo formato
    (DD/MM/AAAA HH:MM:SS), para que las fechas se lean igual en toda la suite.

    La conversión es a la hora local de la máquina donde corre el panel, y no
    a una zona fija escrita en el código: en tu PC eso es Buenos Aires, y si
    algún día esto corre en un servidor con otra hora, va a mostrar la de ahí,
    que es lo correcto.

    Si el texto no se puede parsear se devuelve tal cual: es preferible una
    fecha fea a una fila sin fecha o a una excepción que tire abajo la tabla.
    """
    try:
        momento = datetime.fromisoformat(str(iso))
    except (TypeError, ValueError):
        return str(iso)
    # Sin tzinfo se asume UTC, que es lo que escriben los proyectos.
    if momento.tzinfo is None:
        momento = momento.replace(tzinfo=timezone.utc)
    return momento.astimezone().strftime("%d/%m/%Y %H:%M:%S")


class DashboardRequestHandler(BaseHTTPRequestHandler):
    orchestrator: Orchestrator
    logger_db: LoggerDB

    MAX_CLIENTES_SSE = 12
    MAX_POST_BYTES = 64 * 1024
    _sse_lock = threading.Lock()
    _sse_clientes = 0

    _bg_lock = threading.Lock()
    _bg_running: str | None = None
    # Resultado de la última operación, para mostrarlo arriba del dashboard.
    # Sin esto, apretar un botón que falla "parece que no hace nada".
    _last_result: tuple[str, bool, list[str]] | None = None
    # Salida en vivo de la operación en curso: se va llenando mientras corre.
    _live_lines: list[str] = []
    # El diagnóstico toca la red, así que no se recalcula en cada repintado:
    # se guarda el último y se rehace solo cuando lo pedís.
    _ultimo_diagnostico: list | None = None
    _ultimo_internet: list | None = None
    _ultimas_alertas: list | None = None
    _alertas = None
    _alertas_lock = threading.Lock()
    _incidentes_reg = None
    _incidentes_lock = threading.RLock()
    # La correlación lee cinco bases, arma entidades y aplica reglas. Con
    # doce clientes SSE repintando cada pocos segundos, hacerlo en cada
    # repintado es trabajo repetido para nada, y va a doler bastante más
    # cuando entren Nmap, osquery y Suricata. Se recalcula cada tanto y se
    # reusa en el medio, igual que el estado de la máquina y los procesos.
    _cache_incidentes: list | None = None
    _cache_incidentes_hasta: float = 0.0
    _historial = None
    _historial_lock = threading.Lock()
    _motor = None
    _motor_lock = threading.Lock()
    _ultima_muestra = 0.0
    _muestra_lock = threading.Lock()
    _rango_metricas = 24

    # Segundo freno contra CSRF, independiente de Origin/Fetch-Metadata.
    # Un sitio ajeno puede ENVIAR requests a localhost, pero no puede leer
    # este token HttpOnly ni plantar una cookie para el origen 127.0.0.1.
    _csrf_token = secrets.token_urlsafe(32)
    _csrf_cookie_nombre = "securecenter_csrf"

    HOSTS_PERMITIDOS = frozenset({"127.0.0.1", "localhost", "[::1]", "::1"})

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        pass

    def end_headers(self) -> None:
        """Cabeceras defensivas comunes a todas las respuestas del panel."""
        self.send_header(
            "Set-Cookie",
            f"{self._csrf_cookie_nombre}={self._csrf_token}; Path=/; "
            "HttpOnly; SameSite=Strict",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'",
        )
        super().end_headers()

    # ------------------------------------------------------------ defensas
    #
    # Este panel es el más peligroso de la suite: desde acá se apaga TODA la
    # protección de la máquina y se dispara PÁNICO. Y escucha en localhost,
    # que no quiere decir seguro: cualquier página que visites le puede mandar
    # pedidos. Son las mismas dos defensas que ya tienen SecureDNS y
    # SecureHIPS, y acá faltaban.

    def _host_permitido(self) -> bool:
        """Contra DNS rebinding.

        Sin esto, alguien publica un nombre con TTL 0, te hace entrar, y
        después lo reapunta a 127.0.0.1. A partir de ahí su JavaScript queda
        del mismo origen que este panel y puede LEER las respuestas: qué
        tenés corriendo, qué se bloqueó y cuándo.
        """
        host = (self.headers.get("Host") or "").strip()
        if not host:
            return True
        if host.startswith("["):
            cierre = host.find("]")
            nombre = host[: cierre + 1] if cierre != -1 else host
        else:
            nombre = host.rpartition(":")[0] or host
        return nombre.lower() in self.HOSTS_PERMITIDOS

    def _origen_confiable(self) -> bool:
        """Contra CSRF.

        Pasar los botones de GET a POST fue el primer paso y estuvo bien: un
        GET lo dispara un `<img src="...">` con solo cargar la página. Pero
        POST solo no alcanza: un formulario `application/x-www-form-urlencoded`
        se puede mandar a otro origen sin que el navegador pida permiso, así
        que cualquier web podía autoenviarte un POST a /panic o a /stop-all.
        Lo que sí frena eso es mirar de dónde vino el pedido.
        """
        sitio = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if sitio and sitio not in ("same-origin", "none"):
            return False
        for cabecera in ("Referer", "Origin"):
            valor = (self.headers.get(cabecera) or "").strip()
            if valor and valor != "null":
                origen = urlsplit(valor)
                host = origen.hostname
                try:
                    puerto = origen.port
                except ValueError:
                    return False
                # El puerto también forma parte del origen. Otro servicio web
                # en localhost no tiene por qué poder apagar SecureCenter.
                if (origen.scheme.lower() != "http"
                        or not host
                        or host.lower() not in ("127.0.0.1", "localhost", "::1")
                        or puerto != self.server.server_port):
                    return False
        return True

    def _csrf_cookie_valida(self) -> bool:
        """Token por cookie para no depender solo de cabeceras del navegador."""
        cruda = self.headers.get("Cookie") or ""
        if not cruda:
            return False
        try:
            cookie = SimpleCookie()
            cookie.load(cruda)
            morsel = cookie.get(self._csrf_cookie_nombre)
            recibido = morsel.value if morsel is not None else ""
        except (KeyError, ValueError):
            return False
        return bool(recibido) and hmac.compare_digest(recibido, self._csrf_token)

    def _rechazar(self) -> None:
        self.send_error(403, "pedido rechazado por su origen")

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        path = parsed.path.rstrip("/")
        if path == "/health":
            return self._plain("ok")
        if not self._host_permitido():
            return self._rechazar()
        if path == "/eventos":
            return self._serve_eventos()
        if path in ("/reporte.csv", "/reporte.json"):
            return self._exportar(path, parsed.query)
        if path == "/incidente.json":
            return self._exportar_incidente(parsed.query)
        self._serve_dashboard()

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        path = parsed.path.rstrip("/")
        if (not self._host_permitido() or not self._origen_confiable()
                or not self._csrf_cookie_valida()):
            return self._rechazar()
        try:
            largo = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            return self.send_error(400, "Content-Length inválido")
        if largo < 0:
            return self.send_error(400, "Content-Length inválido")
        if largo > self.MAX_POST_BYTES:
            return self.send_error(413, "cuerpo del pedido demasiado grande")
        routes = {
            "/start-core": ("encender núcleo", lambda o, p: o.execute(o.plan_start_core(), "start_core", progress=p)),
            "/stop-all": ("apagar todo", lambda o, p: o.execute(o.plan_stop_all(), "stop_all", progress=p)),
            "/start-vpn": ("encender VPN", lambda o, p: o.execute(o.plan_start_vpn(), "start_vpn", progress=p)),
            "/stop-vpn": ("apagar VPN", lambda o, p: o.execute(o.plan_stop_vpn(), "stop_vpn", progress=p)),
            "/panic": ("pánico", lambda o, p: o.execute(o.plan_panic(), "panic", progress=p)),
        }
        if path in routes:
            label, op = routes[path]
            return self._start_background(label, op)
        if path == "/start-one":
            return self._individual(start=True)
        if path == "/stop-one":
            return self._individual(start=False)
        if path == "/restart-one":
            return self._individual(start=None)
        if path == "/diagnostico":
            return self._correr_diagnostico()
        if path == "/alerta":
            return self._tocar_alerta()
        if path == "/backup":
            return self._crear_backup()
        if path == "/restaurar":
            return self._restaurar_backup()
        if path == "/regla":
            return self._tocar_regla()
        if path == "/incidente":
            return self._tocar_incidente()
        if path == "/bloquear":
            return self._pedir_bloqueo()
        self._redirect()

    def _leer_form(self) -> dict:
        # do_POST ya validó tamaño y forma de Content-Length. El límite de
        # campos evita convertir un cuerpo pequeño pero patológico en miles de
        # objetos Python innecesarios.
        largo = int(self.headers.get("Content-Length", 0) or 0)
        try:
            cuerpo = self.rfile.read(largo).decode("utf-8") if largo else ""
            return parse_qs(cuerpo, max_num_fields=100)
        except (UnicodeDecodeError, ValueError):
            return {}

    # ------------------------------------------------------- correlación

    def _registro_de_incidentes(self):
        base = DashboardRequestHandler
        if base._incidentes_reg is None:
            with base._incidentes_lock:
                if base._incidentes_reg is None:
                    base._incidentes_reg = mod_corr.RegistroDeIncidentes(
                        self.logger_db._connect())
        return base._incidentes_reg

    SEGUNDOS_DE_CACHE_INCIDENTES = 20

    def _incidentes(self, forzar: bool = False) -> list:
        """Los incidentes de ahora. Se recalculan de los eventos.

        Los eventos son la verdad; el incidente es una lectura de ellos. Lo
        único que se guarda es lo que vos hiciste con cada uno.
        """
        base = DashboardRequestHandler
        ahora = time.time()
        if (not forzar and base._cache_incidentes is not None
                and ahora < base._cache_incidentes_hasta):
            return base._cache_incidentes
        # Dos clientes SSE pueden vencer la caché a la vez. Solo uno relee
        # las cinco bases; el resto reutiliza lo que ese hilo acaba de armar.
        with base._incidentes_lock:
            ahora = time.time()
            if (not forzar and base._cache_incidentes is not None
                    and ahora < base._cache_incidentes_hasta):
                return base._cache_incidentes
            try:
                externos = getattr(self.orchestrator.cfg, "externos", None)
                eventos = mod_ad.recolectar(
                    self.orchestrator.projects,
                    pihole_db=getattr(externos, "pihole_db", "") or "",
                    suricata_eve=getattr(externos, "suricata_eve", "") or "")
                mapa = mod_ent.agrupar(eventos)
                incidentes = mod_corr.correlacionar(mapa)
                incidentes = self._registro_de_incidentes().sincronizar(incidentes)
                base._cache_incidentes = incidentes
                base._cache_incidentes_hasta = ahora + self.SEGUNDOS_DE_CACHE_INCIDENTES
                return incidentes
            except Exception as exc:  # noqa: BLE001
                print(f"[SecureCenter] no pude correlacionar: {exc}")
                return []

    def _tocar_incidente(self) -> None:
        datos = self._leer_form()
        huella = (datos.get("h") or [""])[0]
        estado = (datos.get("e") or [""])[0]
        if huella and estado:
            try:
                self._registro_de_incidentes().marcar(huella, estado)
                # Sin esto, marcarlo visto no se vería hasta que venza la
                # caché, y parecería que el botón no hizo nada.
                DashboardRequestHandler._cache_incidentes_hasta = 0.0
            except Exception as exc:  # noqa: BLE001
                print(f"[SecureCenter] no pude marcar el incidente: {exc}")
        self._redirect()

    def _pedir_bloqueo(self) -> None:
        """Le pide a SecureHIPS que bloquee la IP de afuera de un incidente.

        ES EL PRIMER LUGAR DONDE SECURECENTER PUEDE CAMBIAR ALGO DEL SISTEMA.
        Hasta acá solo miraba. Por eso arranca desde un click y no desde un
        temporizador: hay una persona que vio la evidencia y decidió.

        Toda la política vive en `respuesta.py` y no acá: qué IP se puede
        pedir, cuándo no se puede, y con qué motivo queda anotada. Este método
        es el cable.
        """
        from . import hips_client as mod_hips
        from . import respuesta as mod_resp

        huella = (self._leer_form().get("h") or [""])[0]
        incidente = next((i for i in self._incidentes() if i.huella == huella), None)
        try:
            _ok, detalle = mod_resp.pedir(
                incidente, mod_hips.desde_config(self.orchestrator.cfg))
        except Exception as exc:  # noqa: BLE001 - un panel no se cae por esto
            _ok, detalle = False, f"no pude pedir el bloqueo: {exc}"
        # Queda en el historial de SecureCenter además de en el de SecureHIPS.
        # Lo que se pidió desde acá tiene que poder leerse desde acá, aunque
        # el HIPS después lo haya rechazado.
        print(f"[SecureCenter] bloqueo pedido para {huella}: {detalle}")
        try:
            self.logger_db.log_event("bloqueo pedido a SecureHIPS", detalle,
                                     ok=_ok)
        except Exception:  # noqa: BLE001
            pass
        self._redirect()

    def _exportar_incidente(self, query: str) -> None:
        """Un incidente entero como JSON, con toda su evidencia.

        Es el formato en que se lleva a otra herramienta o se adjunta a un
        reporte: sin maquillar, con los eventos crudos que lo sostienen.
        """
        huella = (parse_qs(query).get("h") or [""])[0]
        incidente = next((i for i in self._incidentes() if i.huella == huella), None)
        cuerpo = json.dumps(
            incidente.como_dict() if incidente else {"error": "no existe"},
            ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(200 if incidente else 404)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        # El query string es entrada del usuario y no puede entrar crudo en
        # una cabecera HTTP (CRLF/header injection). La huella válida sale de
        # un incidente ya construido por nosotros.
        nombre = f"incidente-{incidente.huella}.json" if incidente else "incidente-no-encontrado.json"
        self.send_header("Content-Disposition", f'attachment; filename="{nombre}"')
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(cuerpo)
        self.close_connection = True

    def _bloque_incidentes(self) -> tuple[str, str]:
        incidentes = self._incidentes()
        sin_ver = self._registro_de_incidentes().sin_ver(incidentes)
        chapa = f"<span class='chapa'>{sin_ver}</span>" if sin_ver else ""
        if not incidentes:
            return ("<p class='bien'>Ninguna regla encontró una historia que "
                    "cruce dos herramientas. Es lo normal: la correlación "
                    "existe para lo que pasa poco.</p>"), chapa

        tarjetas = []
        for i in incidentes:
            color = {"alta": "#ff8a8a", "media": "#e3b341"}.get(i.gravedad, "#7bd88f")
            apagado = " style='opacity:0.55'" if i.estado == mod_corr.CERRADO else ""
            filas = "".join(
                f"<tr><td class='fecha'>{html_lib.escape(formatear_fecha_ts(e.ts))}</td>"
                f"<td>{html_lib.escape(e.fuente)}</td>"
                f"<td>{html_lib.escape(e.detalle)}</td></tr>"
                for e in sorted(i.evidencias, key=lambda x: x.ts)[:12]
            )
            botones = "".join(
                f"<form method='post' action='/incidente'>"
                f"<input type='hidden' name='h' value='{i.huella}'>"
                f"<input type='hidden' name='e' value='{estado}'>"
                f"<button type='submit'>{etiqueta}</button></form>"
                for estado, etiqueta in ((mod_corr.VISTO, "Marcar visto"),
                                         (mod_corr.CERRADO, "Marcar resuelto"))
                if estado != i.estado
            )
            tarjetas.append(
                f"<div class='alerta'{apagado}>"
                f"<div class='alerta-cab'><span style='color:{color}'>&#9679;</span> "
                f"<b>{html_lib.escape(i.titulo)}</b>"
                f"<span class='subtitle'> &middot; confianza {i.confianza}%"
                f" &middot; {html_lib.escape(i.estado)}</span></div>"
                f"<div class='subtitle'>{html_lib.escape(i.que_significa)}</div>"
                f"<table style='margin-top:0.5rem'>{filas}</table>"
                f"<div class='alerta-botones'>{botones}"
                f"{self._boton_de_bloqueo(i)}"
                f"<a class='boton-link' href='/incidente.json?h={i.huella}'>"
                f"Exportar JSON</a></div></div>")
        return "".join(tarjetas), chapa

    def _boton_de_bloqueo(self, incidente) -> str:
        """El botón de "pedir bloqueo", o la explicación de por qué no está.

        Fase 4 del punto 9. Cuando no se puede, se dice POR QUÉ en el mismo
        lugar donde estaría el botón: un botón que falta sin explicación hace
        creer que el programa está roto, y uno que dice "esto no se bloquea en
        el firewall, se bloquea en el DNS" enseña algo.
        """
        from . import respuesta as mod_resp

        ip, porque = mod_resp.candidata(incidente)
        if not ip:
            return (f"<span class='subtitle' style='align-self:center'>"
                    f"Sin bloqueo: {html_lib.escape(porque)}</span>")
        return (
            f"<form method='post' action='/bloquear' "
            f"onsubmit=\"return confirm('¿Pedirle a SecureHIPS que bloquee "
            f"{ip} por 4 horas?')\">"
            f"<input type='hidden' name='h' value='{incidente.huella}'>"
            f"<button type='submit'>Pedir bloqueo de {html_lib.escape(ip)}</button>"
            f"</form>")

    # ------------------------------------- rendimiento y automatizaciones

    def _historial_de_metricas(self):
        base = DashboardRequestHandler
        if base._historial is None:
            with base._historial_lock:
                if base._historial is None:
                    base._historial = mod_met.Historial(self.logger_db._connect())
        return base._historial

    def _motor_de_reglas(self):
        base = DashboardRequestHandler
        if base._motor is None:
            with base._motor_lock:
                if base._motor is None:
                    base._motor = mod_auto.Motor(ejecutor=self._ejecutar_accion)
        return base._motor

    def _ejecutar_accion(self, accion: str, objetivo: str) -> tuple[bool, str]:
        """Lo que una regla puede hacer de verdad. Nunca lanza."""
        o = self.orchestrator
        if accion == "avisar":
            self.logger_db.log_event("automatizacion", f"disparó por {objetivo}", True)
            return True, "anotado en el registro"
        if accion == "backup":
            marca = datetime.now().strftime("%Y%m%d-%H%M%S")
            datos = mod_backup.crear(
                o.projects, self._carpeta_de_backups() / f"auto-{marca}.zip")
            return datos["total"] > 0, f"copia con {datos['total']} archivo(s)"
        if accion == "reiniciar":
            if objetivo not in {s.key for s in PROJECT_SPECS}:
                return False, "esa acción necesita un servicio concreto"
            pasos = o.plan_stop_one(objetivo) + o.plan_start_one(objetivo)
            resultado = o.execute(pasos, f"auto_reiniciar_{objetivo}")
            procesos.limpiar_cache()
            # `sirvió` mira si el reinicio funcionó, no si se ejecutó. Es lo
            # que hace que la regla se apague sola cuando no arregla nada.
            return bool(getattr(resultado, "ok", False)), f"reinicié {objetivo}"
        return False, f"no sé hacer «{accion}»"

    def _tomar_muestra_y_evaluar(self, health, maquina_datos) -> None:
        """Se llama al armar los fragmentos, con freno de tiempo propio.

        Va acá y no en un hilo aparte a propósito: el panel ya se repinta
        solo, así que no hace falta otro hilo que pueda quedar colgado. Si
        nadie mira el panel tampoco se toman muestras, y está bien: lo que
        interesa es la tendencia mientras la herramienta se usa.
        """
        base = DashboardRequestHandler
        ahora = time.time()
        # El servidor HTTP es multi-hilo: check+set tiene que ser atómico o
        # dos pestañas pueden evaluar la misma automatización a la vez.
        with base._muestra_lock:
            if ahora - base._ultima_muestra < mod_met.SEGUNDOS_ENTRE_MUESTRAS:
                return
            base._ultima_muestra = ahora
        try:
            historial = self._historial_de_metricas()
            historial.guardar(maquina_datos, ahora)
            historial.podar(ahora=ahora)
        except Exception as exc:  # noqa: BLE001
            print(f"[SecureCenter] no pude guardar la métrica: {exc}")
        try:
            self._motor_de_reglas().evaluar({
                "health": health,
                "alertas": DashboardRequestHandler._ultimas_alertas or [],
                "revisiones": DashboardRequestHandler._ultimo_diagnostico,
                "puntaje": (mod_diag.puntaje(DashboardRequestHandler._ultimo_diagnostico)
                            if DashboardRequestHandler._ultimo_diagnostico else None),
                "maquina": maquina_datos,
            }, ahora)
        except Exception as exc:  # noqa: BLE001
            print(f"[SecureCenter] falló el motor de reglas: {exc}")

    def _tocar_regla(self) -> None:
        datos = self._leer_form()
        clave = (datos.get("r") or [""])[0]
        regla = self._motor_de_reglas().por_clave(clave)
        if regla is not None:
            regla.habilitado = not regla.habilitado
            # Prender una regla que se había apagado sola es decir "ya lo
            # arreglé, volvé a intentar": hay que limpiarle el contador.
            if regla.habilitado:
                regla.apagada_por_fallas = False
                regla.fallas_seguidas = 0
        self._redirect()

    def _bloque_rendimiento(self) -> str:
        try:
            cuerpo = mod_met.bloque(self._historial_de_metricas(),
                                    DashboardRequestHandler._rango_metricas)
        except Exception as exc:  # noqa: BLE001
            return f"<p class='warn'>No pude dibujar los gráficos: {html_lib.escape(str(exc))}</p>"

        motor = self._motor_de_reglas()
        filas = []
        for regla in motor.reglas:
            disp = mod_auto.DISPARADORES.get(regla.disparador, ("", "", None))
            acc = mod_auto.ACCIONES.get(regla.accion, ("", ""))
            if regla.apagada_por_fallas:
                estado = "<span class='chip mal'>se apagó sola</span>"
            elif regla.habilitado:
                estado = "<span class='chip ok'>activa</span>"
            else:
                estado = "<span class='chip na'>apagada</span>"
            filas.append(
                f"<div class='alerta'><div class='alerta-cab'>{estado} "
                f"<b>{html_lib.escape(regla.titulo())}</b></div>"
                f"<div class='subtitle'>{html_lib.escape(disp[1])}</div>"
                f"<div class='subtitle'>{html_lib.escape(acc[1])}</div>"
                f"<div class='alerta-botones'>"
                f"<form method='post' action='/regla'>"
                f"<input type='hidden' name='r' value='{html_lib.escape(regla.clave)}'>"
                f"<button type='submit'>"
                f"{'Apagar' if regla.habilitado else 'Activar'}</button></form>"
                f"</div></div>")

        hechos = "".join(
            f"<tr><td class='fecha'>{html_lib.escape(formatear_fecha(datetime.fromtimestamp(h['cuando'], timezone.utc).isoformat()))}</td>"
            f"<td>{html_lib.escape(h['regla'])}</td>"
            f"<td>{'sirvió' if h.get('sirvio') else 'no arregló nada'}</td>"
            f"<td>{html_lib.escape(h.get('detalle', ''))}</td></tr>"
            for h in motor.historial[:20]
        )
        tabla = (f"<table style='margin-top:0.6rem'><tr><th>Cuándo</th>"
                 f"<th>Regla</th><th>Resultado</th><th>Detalle</th></tr>"
                 f"{hechos}</table>" if hechos else
                 "<p class='subtitle'>Ninguna regla se disparó todavía.</p>")

        return (
            f"<h2>Rendimiento</h2>{cuerpo}"
            f"<h2 style='margin-top:1.6rem'>Automatizaciones</h2>"
            f"<p class='subtitle' style='margin-top:0'>Los disparadores y las "
            f"acciones son listas cerradas: no hay nada que escribir, así que "
            f"no hay nada que pueda salir inválido ni ejecutar código. "
            f"<b>Todas vienen apagadas.</b> Cada regla espera 10 minutos entre "
            f"disparos, no corre más de 3 veces por hora, y si tres intentos "
            f"seguidos no arreglan nada se apaga sola.</p>"
            f"{''.join(filas)}"
            f"<h2 style='margin-top:1.4rem'>Qué hicieron</h2>{tabla}"
        )

    # ------------------------------------------------ reportes y backup

    def _carpeta_de_backups(self):
        carpeta = Path(self.orchestrator.cfg.resolve_path("data/backups"))
        carpeta.mkdir(parents=True, exist_ok=True)
        return carpeta

    def _exportar(self, ruta: str, query: str) -> None:
        """El reporte, como descarga. Se arma en el momento."""
        try:
            dias = int((parse_qs(query).get("dias") or ["7"])[0])
        except ValueError:
            dias = 7
        # Solo los rangos que ofrece el panel: un `dias=100000` armaría en
        # memoria el historial entero antes de mandar el primer byte.
        if dias not in [d for d, _ in mod_rep.RANGOS]:
            dias = 7
        filas = mod_rep.recolectar(self.orchestrator.projects, dias)
        if ruta.endswith(".json"):
            cuerpo, tipo, ext = mod_rep.a_json(filas, dias), "application/json", "json"
        else:
            cuerpo, tipo, ext = mod_rep.a_csv(filas), "text/csv", "csv"
        nombre = mod_rep.nombre_de_archivo(dias, ext)
        self.send_response(200)
        self.send_header("Content-Type", f"{tipo}; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{nombre}"')
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(cuerpo)
        self.close_connection = True

    def _crear_backup(self) -> None:
        incluir = bool((self._leer_form().get("historial") or [""])[0])

        def op(o: Orchestrator, progreso):
            marca = datetime.now().strftime("%Y%m%d-%H%M%S")
            destino = self._carpeta_de_backups() / f"suite-{marca}.zip"
            progreso("guardando configuración y listas de los proyectos disponibles...")
            datos = mod_backup.crear(o.projects, destino, incluir_historial=incluir)
            progreso(f"{datos['total']} archivo(s) en {destino.name}")
            for salteado in datos["salteados"]:
                progreso(f"  salteado: {salteado}")
            progreso("los .env NO se guardan: ahí viven los tokens")
            return type("R", (), {"ok": datos["total"] > 0,
                                  "lines": [destino.name]})()

        self._start_background("crear copia de seguridad", op)

    def _restaurar_backup(self) -> None:
        nombre = (self._leer_form().get("a") or [""])[0]
        carpeta = self._carpeta_de_backups()
        archivo = (carpeta / nombre).resolve()
        # El nombre viene del formulario: sin este chequeo, un "..\..\algo"
        # dejaría restaurar cualquier zip del disco.
        if (not nombre or archivo.suffix.lower() != ".zip"
                or not archivo.is_relative_to(carpeta.resolve())
                or not archivo.is_file()):
            return self._redirect()

        def op(o: Orchestrator, progreso):
            progreso(f"restaurando desde {nombre}...")
            datos = mod_backup.restaurar(o.projects, archivo)
            progreso(datos["detalle"])
            return type("R", (), {"ok": datos["ok"], "lines": [datos["detalle"]]})()

        self._start_background(f"restaurar {nombre}", op)

    def _bloque_reportes(self) -> str:
        enlaces = "".join(
            f"<div class='dato'><span class='dato-k'>{html_lib.escape(txt)}</span>"
            f"<span><a href='/reporte.csv?dias={d}'>CSV</a> &middot; "
            f"<a href='/reporte.json?dias={d}'>JSON</a></span></div>"
            for d, txt in mod_rep.RANGOS
        )
        try:
            copias = sorted(self._carpeta_de_backups().glob("*.zip"), reverse=True)
        except OSError:
            copias = []
        if copias:
            filas = "".join(
                f"<tr><td>{html_lib.escape(c.name)}</td>"
                f"<td class='num'>{round(c.stat().st_size / 1024)} KB</td>"
                f"<td><form method='post' action='/restaurar' "
                f"onsubmit=\"return confirm('Restaurar esta copia pisa la "
                f"configuración actual de los proyectos disponibles. "
                f"Antes se guarda una copia. ¿Seguir?')\">"
                f"<input type='hidden' name='a' value='{html_lib.escape(c.name)}'>"
                f"<button type='submit'>Restaurar</button></form></td></tr>"
                for c in copias[:15]
            )
            tabla = (f"<table style='margin-top:0.6rem'><tr><th>Archivo</th>"
                     f"<th class='num'>Tamaño</th><th></th></tr>{filas}</table>")
        else:
            tabla = "<p class='subtitle'>Todavía no hay ninguna copia.</p>"
        return (
            f"<h2>Exportar lo que pasó</h2>"
            f"<div class='ficha' style='border-top:0'>{enlaces}</div>"
            f"<h2 style='margin-top:1.6rem'>Copias de seguridad</h2>"
            f"<p class='subtitle' style='margin-top:0'>Se guarda la "
            f"configuración y tus listas manuales de los proyectos disponibles. "
            f"Los <code>.env</code> quedan afuera siempre: ahí viven el token "
            f"de Telegram, la clave de AbuseIPDB y el token de SecureHIPS.</p>"
            f"<form method='post' action='/backup'>"
            f"<button class='ok-btn' type='submit'>Crear copia ahora</button></form> "
            f"<form method='post' action='/backup'>"
            f"<input type='hidden' name='historial' value='1'>"
            f"<button type='submit'>Crear copia con el historial (pesa mucho más)</button>"
            f"</form>{tabla}"
        )

    def _correr_diagnostico(self) -> None:
        """Se corre en segundo plano: toca la red y puede tardar."""
        def op(o: Orchestrator, progreso):
            progreso("revisando proyectos, puertos, feeds, disco e internet...")
            internet = mod_diag.estado_de_internet()
            revisiones = mod_diag.revisar(o.cfg, o.projects, internet=internet)
            DashboardRequestHandler._ultimo_diagnostico = revisiones
            DashboardRequestHandler._ultimo_internet = internet
            puntos = mod_diag.puntaje(revisiones)
            progreso(f"puntaje: {puntos}/100. {mod_diag.resumen(revisiones)}")
            for r in revisiones:
                if r["estado"] != mod_diag.OK:
                    progreso(f"  [{r['estado']}] {r['nombre']}: {r['detalle']}")
            # `ok` mira si hay algo ROTO, no si hay avisos: un diagnóstico que
            # queda en rojo por una librería opcional que falta se aprende a
            # ignorar en dos días.
            roto = any(r["estado"] == mod_diag.MAL for r in revisiones)
            return type("R", (), {"ok": not roto,
                                  "lines": [f"puntaje {puntos}/100"]})()

        self._start_background("diagnóstico", op)

    def _tocar_alerta(self) -> None:
        datos = self._leer_form()
        huella = (datos.get("h") or [""])[0]
        estado = (datos.get("e") or [""])[0]
        if huella and estado:
            try:
                self._registro_de_alertas().marcar(huella, estado)
            except Exception as exc:  # noqa: BLE001
                print(f"[SecureCenter] no pude marcar la alerta: {exc}")
        self._redirect()

    def _individual(self, start) -> None:
        """start=True enciende, False apaga, None reinicia."""
        key = (self._leer_form().get("p") or [""])[0]
        
        # Contra PROJECT_SPECS y no contra una tupla escrita a mano: agregar
        # un proyecto al registro tiene que alcanzar para que su botón ande,
        # sin acordarse de esta línea.
        if key not in {s.key for s in PROJECT_SPECS}:
            return self._redirect()
        verb = "reiniciar" if start is None else ("iniciar" if start else "detener")

        def op(o: Orchestrator, progreso):
            if start is None:
                # Apagar y encender, en ese orden y en la misma operación. No
                # es lo mismo que apretar los dos botones: entre uno y otro el
                # usuario puede irse, y quedaría todo apagado creyendo que
                # reinició.
                steps = o.plan_stop_one(key) + o.plan_start_one(key)
            else:
                steps = o.plan_start_one(key) if start else o.plan_stop_one(key)
            resultado = o.execute(steps, f"{verb}_{key}", progress=progreso)
            # El PID cambió: mostrar el consumo del proceso anterior durante
            # dos segundos sería mentir justo cuando se está mirando si el
            # reinicio salió bien.
            procesos.limpiar_cache()
            return resultado

        self._start_background(f"{verb} {key}", op)

    def _start_background(self, label: str, op) -> None:
        base = DashboardRequestHandler
        with base._bg_lock:
            if base._bg_running is not None:
                self.logger_db.log_event(
                    "ocupado", f"ya hay una operación en curso ({base._bg_running}); '{label}' ignorado", ok=False
                )
                return self._redirect()
            base._bg_running = label
            # Consola en vivo: arranca vacía y se va llenando mientras la
            # operación corre. La página se refresca sola cada 5 segundos y
            # muestra lo que haya hasta ese momento.
            base._live_lines = []

        def anotar(linea: str) -> None:
            with base._bg_lock:
                base._live_lines.append(linea)

        def runner():
            try:
                res = op(self.orchestrator, anotar)
                with base._bg_lock:
                    base._last_result = (label, bool(getattr(res, "ok", True)), list(getattr(res, "lines", [])))
            except Exception as exc:  # noqa: BLE001
                self.logger_db.log_event(label, f"error inesperado: {exc}", ok=False)
                with base._bg_lock:
                    base._last_result = (label, False, [f"error inesperado: {exc}"])
            finally:
                with base._bg_lock:
                    base._bg_running = None

        threading.Thread(target=runner, daemon=True).start()
        self._redirect()

    def _plain(self, text: str) -> None:
        body = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _redirect(self) -> None:
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def _fragmentos(self) -> dict:
        """Los pedazos de la página que cambian solos, con una firma.

        Los usan el HTML inicial y el canal de eventos. La firma (`revision`)
        existe para no mandar por el canal lo mismo que ya está en pantalla:
        sin eso, cada cinco segundos se repintaría todo el DOM, se perdería la
        selección de texto y el scroll de la consola volvería arriba, que es
        justo lo que se venía a arreglar.
        """
        cfg = self.orchestrator.cfg
        projects = self.orchestrator.projects
        health = state_snapshot(cfg)

        base = DashboardRequestHandler
        with base._bg_lock:
            bg = base._bg_running
            last = base._last_result
            vivas = list(base._live_lines)

        # Tres estados, no dos: "parcial" es el caso de la VPN con su
        # dashboard arriba pero el túnel sin conectar (antes se mostraba
        # "activo" y era engañoso).
        ETIQUETAS = {
            ACTIVO: ("#7bd88f", "operativo"),
            PARCIAL: ("#e0b341", "degradado"),
            APAGADO: ("#9aa0a6", "detenido"),
        }

        def dot(estado: str, disponible: bool = True) -> str:
            if not disponible:
                return "<span style='color:#9aa0a6'>&#9679; no disponible</span>"
            color, txt = ETIQUETAS.get(estado, ETIQUETAS[APAGADO])
            return f"<span style='color:{color}'>&#9679; {txt}</span>"

        cards = "".join(
            f"<div class='card'><div class='value' style='font-size:1.1rem'>"
            f"{dot(health[s.key], projects[s.key].found)}</div>"
            f"<div class='label'>{s.display_name}<br><span style='font-size:0.8rem'>{s.role}</span></div></div>"
            for s in PROJECT_SPECS
        )

        # La consola: mientras la operación corre muestra la salida EN VIVO
        # (ámbar), y al terminar el mismo bloque queda verde o rojo con el
        # detalle completo. Antes no se veía nada hasta el final, y una
        # operación de varios minutos parecía colgada.
        if bg:
            titulo = f"EN CURSO: {html_lib.escape(bg)}"
            cuerpo = vivas or ["arrancando..."]
            clase = "resultado run"
        elif last:
            etiqueta, ok_last, lineas = last
            clase = "resultado ok" if ok_last else "resultado err"
            titulo = ("OK" if ok_last else "FALLÓ") + f": {html_lib.escape(etiqueta)}"
            cuerpo = lineas
        else:
            clase = titulo = ""
            cuerpo = []

        if titulo:
            # Se muestran las últimas líneas y se sigue sola hacia abajo, como
            # una consola de verdad: lo último que pasó siempre a la vista.
            detalle = "".join(f"<div>{html_lib.escape(l)}</div>" for l in cuerpo[-200:])
            last_line = (
                f"<div class='{clase}'><strong>{titulo}</strong>"
                f"<pre class='consola' id='consola'>{detalle}</pre></div>"
            )
        else:
            last_line = ""

        sections = "".join(
            self._project_section(s, projects, health[s.key], operacion_en_curso=bool(bg))
            for s in PROJECT_SPECS
        )

        timeline = collect_logs(cfg, projects, per_source=40)[:60]
        if timeline:
            # Los data-* son lo que el filtro del navegador mira. Van en el
            # HTML y no se recalculan en JavaScript porque parsear la fecha
            # formateada del lado del cliente sería volver a hacer un trabajo
            # que acá ya está hecho, y con más chances de equivocarse.
            rows = "".join(
                f"<tr data-proyecto='{html_lib.escape(r.project)}' "
                f"data-tipo='{html_lib.escape(r.kind)}' "
                f"data-epoch='{_a_epoch(r.timestamp):.0f}'>"
                f"<td class='fecha'>{html_lib.escape(formatear_fecha(r.timestamp))}</td>"
                f"<td>{html_lib.escape(r.project)}</td>"
                f"<td>{html_lib.escape(r.kind)}</td>"
                f"<td>{html_lib.escape(r.detail)}</td></tr>"
                for r in timeline
            )
        else:
            rows = "<tr><td colspan='4'>Sin eventos todavía (o los proyectos nunca corrieron).</td></tr>"

        opciones_proyecto = "".join(
            f"<option value='{html_lib.escape(v)}'>{html_lib.escape(v)}</option>"
            for v in sorted({r.project for r in timeline}))
        opciones_tipo = "".join(
            f"<option value='{html_lib.escape(v)}'>{html_lib.escape(v)}</option>"
            for v in sorted({r.kind for r in timeline}))

        lista_alertas, chapa = self._bloque_alertas(projects, health)
        lista_incidentes, chapa_inc = self._bloque_incidentes()
        # El diagnóstico también va por el canal. Sin esto, corrías la
        # revisión, terminaba, y la pestaña seguía diciendo "todavía no lo
        # corriste" hasta que recargabas la página a mano.
        bloque_diagnostico = self._bloque_diagnostico()
        bloque_agentes = mod_agentes.bloque(projects.get("agente"))
        maquina_datos = sistema.snapshot()
        maquina = self._bloque_maquina(maquina_datos)
        contadores = self._bloque_contadores(projects)
        self._tomar_muestra_y_evaluar(health, maquina_datos)

        not_found = [s.display_name for s in PROJECT_SPECS if not projects[s.key].found]
        warn = (
            f"<p class='warn'>No encontré: {', '.join(not_found)}. Revisá las rutas en config/config.yaml.</p>"
            if not_found else ""
        )

        return {
            # La firma incluye la cantidad de líneas vivas para que la consola
            # se siga viendo avanzar durante una operación larga, que es el
            # momento en que uno más mira la pantalla.
            # La revisión incluye ahora los contadores y el estado de la
            # máquina: si no, el número de bloqueos de hoy se quedaría quieto
            # hasta que cambiara alguna otra cosa.
            "revision": (f"{sorted(health.items())}|{bg}|{len(vivas)}|"
                         f"{len(timeline)}|{bool(last)}|{hash(maquina)}|"
                         f"{hash(contadores)}|{hash(lista_alertas)}|{hash(lista_incidentes)}|"
                         f"{hash(bloque_diagnostico)}|{hash(bloque_agentes)}"),
            "maquina": maquina,
            "contadores": contadores,
            "alertas": lista_alertas,
            "chapa": chapa,
            "incidentes": lista_incidentes,
            "chapa_inc": chapa_inc,
            "diagnostico": bloque_diagnostico,
            "agentes": bloque_agentes,
            "opciones_proyecto": opciones_proyecto,
            "opciones_tipo": opciones_tipo,
            "cards": cards,
            "globalbar": self._globalbar(health, operacion_en_curso=bool(bg)),
            "consola": last_line,
            "secciones": sections,
            "timeline": rows,
            "aviso": warn,
        }

    def _ficha(self, spec, port: int, estado_key: str) -> str:
        """PID, puerto, RAM, CPU, tiempo activo y versión de ese servicio.

        Es lo que convierte "está corriendo" en algo que se puede investigar.
        Cuando algo va lento, la pregunta siguiente siempre es cuál de los
        cinco se lo está comiendo, y hasta ahora había que ir al Administrador
        de tareas y adivinar entre cinco `python.exe`.
        """
        projects = self.orchestrator.projects
        version = procesos.version_de(projects.get(spec.key))
        datos = self._detalles_de_procesos().get(spec.key, {})

        campos = [("Puerto", str(port))]
        if estado_key == APAGADO:
            campos.append(("Estado", "apagado"))
        elif not procesos.disponible():
            campos.append(("Consumo", "instalá psutil para verlo"))
        elif datos.get("sin_acceso"):
            # Pasa cuando el proceso es de otro usuario o corre elevado y
            # SecureCenter no. Decirlo es mejor que mostrar 0 MB.
            campos.append(("PID", str(datos.get("pid", "-"))))
            campos.append(("Consumo", "sin permisos para verlo"))
        elif datos.get("pid"):
            campos += [
                ("PID", str(datos["pid"])),
                ("RAM", f"{datos['ram_mb']} MB"),
                ("CPU", f"{datos['cpu_pct']}%"),
                ("Activo", datos["activo_hace"]),
            ]
        # "sin versionar" ocupaba espacio sin aportar información. Cuando el
        # paquete publique una versión real vuelve a aparecer solo.
        if version and version != "sin versionar":
            campos.append(("Versión", version))

        celdas = "".join(
            f"<div class='dato'><span class='dato-k'>{html_lib.escape(k)}</span>"
            f"<span class='dato-v'>{html_lib.escape(v)}</span></div>"
            for k, v in campos
        )
        return f"<div class='ficha'>{celdas}</div>"

    def _detalles_de_procesos(self) -> dict:
        """Una sola pasada por los procesos para las cinco fichas.

        Sin esto, pintar la página consultaría la tabla de procesos del
        sistema cinco veces seguidas, y con doce clientes SSE conectados eso
        se multiplica.
        """
        cfg = self.orchestrator.cfg
        return procesos.snapshot({
            "proxy": cfg.ports.proxy_service,
            "dns": cfg.ports.dns_dashboard,
            "vpn": cfg.ports.vpn_dashboard,
            "hips": cfg.ports.hips_dashboard,
            "intel": cfg.ports.intel_dashboard,
        })

    # ------------------------------------------------- estado de la máquina

    def _bloque_alertas(self, projects, health) -> tuple[str, str]:
        """Las alertas vigentes, con sus botones. Nunca lanza."""
        try:
            registro = self._registro_de_alertas()
            # Las revisiones caras (red) NO se recalculan acá: se usan las del
            # último diagnóstico si lo corriste. Sin eso, cada repintado por
            # SSE abriría cinco conexiones a internet.
            detectadas = mod_alertas.detectar(
                self.orchestrator.cfg, projects, health,
                DashboardRequestHandler._ultimo_diagnostico)
            vigentes = registro.sincronizar(detectadas)
            DashboardRequestHandler._ultimas_alertas = vigentes
            sin_atender = registro.sin_atender()
        except Exception as exc:  # noqa: BLE001
            return f"<p class='warn'>No pude armar las alertas: {html_lib.escape(str(exc))}</p>", ""

        chapa = (f"<span class='chapa'>{sin_atender}</span>" if sin_atender else "")
        evaluacion = ("<p class='subtitle'>Última evaluación: "
                      f"{datetime.now().astimezone().strftime('%d/%m/%Y %H:%M:%S')}.</p>")
        # Las resueltas y silenciadas siguen en la lista pero apagadas: que
        # desaparezcan haría imposible acordarse de qué silenciaste.
        visibles = [a for a in vigentes if a["estado"] != mod_alertas.RESUELTA]
        if not visibles:
            return (evaluacion + "<p class='bien'>Nada que atender. Las condiciones que "
                    "generan alertas no se están cumpliendo.</p>"), chapa

        filas = []
        for a in visibles:
            color = mod_alertas.COLORES.get(a["gravedad"], "#9aa0a6")
            apagada = " style='opacity:0.5'" if a["estado"] == mod_alertas.SILENCIADA else ""
            desde = formatear_fecha(
                datetime.fromtimestamp(a["primera"], timezone.utc).isoformat())
            botones = "".join(
                f"<form method='post' action='/alerta'>"
                f"<input type='hidden' name='h' value='{a['huella']}'>"
                f"<input type='hidden' name='e' value='{estado}'>"
                f"<button type='submit'>{etiqueta}</button></form>"
                for estado, etiqueta in (
                    (mod_alertas.LEIDA, "Marcar leída"),
                    (mod_alertas.SILENCIADA, "Silenciar"),
                    (mod_alertas.RESUELTA, "Resolver"),
                )
                if estado != a["estado"]
            )
            filas.append(
                f"<div class='alerta'{apagada}>"
                f"<div class='alerta-cab'>"
                f"<span style='color:{color}'>&#9679;</span> "
                f"<b>{html_lib.escape(a['titulo'])}</b>"
                f"<span class='subtitle'> &middot; desde {html_lib.escape(desde)}"
                f" &middot; {html_lib.escape(a['estado'])}</span></div>"
                f"<div class='subtitle'>{html_lib.escape(a['detalle'])}</div>"
                + (f"<div class='arreglo'>{html_lib.escape(a['que_hacer'])}</div>"
                   if a.get("que_hacer") else "")
                + f"<div class='alerta-botones'>{botones}</div></div>"
            )
        return evaluacion + "".join(filas), chapa

    def _registro_de_alertas(self):
        """Una sola instancia, sobre la misma base que el registro de eventos.

        Se guarda en la clase y no por pedido: crear la conexión y el CREATE
        TABLE en cada repintado, con doce clientes SSE, sería abrir y cerrar
        la base decenas de veces por minuto.
        """
        base = DashboardRequestHandler
        if base._alertas is None:
            with base._alertas_lock:
                if base._alertas is None:
                    base._alertas = mod_alertas.RegistroDeAlertas(
                        self.logger_db._connect())
        return base._alertas

    def _bloque_diagnostico(self) -> str:
        revisiones = DashboardRequestHandler._ultimo_diagnostico
        if revisiones is None:
            return ("<p class='subtitle'>Todavía no lo corriste. El botón de "
                    "arriba revisa los proyectos, los puertos, los feeds, el "
                    "disco, la memoria y si se llega a internet.</p>")
        puntos = mod_diag.puntaje(revisiones)
        color = "#7bd88f" if puntos >= 90 else "#e3b341" if puntos >= 70 else "#ff8a8a"
        filas = "".join(
            f"<tr><td>{html_lib.escape(r['nombre'])}</td>"
            f"<td><span class='chip {r['estado']}'>{r['estado']}</span></td>"
            f"<td>{html_lib.escape(r['detalle'])}</td>"
            f"<td class='arreglo'>{html_lib.escape(r.get('arreglo') or '-')}</td></tr>"
            for r in revisiones
        )
        internet = "".join(
            f"<div class='dato'><span class='dato-k'>{html_lib.escape(s['nombre'])}</span>"
            f"<span class='dato-v' style='color:{'#7bd88f' if s['ok'] else '#ff8a8a'}'>"
            f"{'alcanzable' if s['ok'] else 'sin acceso'}</span></div>"
            for s in DashboardRequestHandler._ultimo_internet or ()
        )
        return (
            f"<div class='hoy'><div class='hoy-num' style='color:{color}'>{puntos}"
            f"<span style='font-size:1rem;color:#9aa0a6'>/100</span></div>"
            f"<div class='label'>{html_lib.escape(mod_diag.resumen(revisiones))}</div></div>"
            + (f"<div class='ficha'>{internet}</div>" if internet else "")
            + f"<table style='margin-top:1rem'><tr><th>Qué</th><th>Estado</th>"
              f"<th>Detalle</th><th>Cómo se arregla</th></tr>{filas}</table>"
        )

    def _bloque_maquina(self, datos: dict | None = None) -> str:
        """CPU, RAM, disco y hace cuánto está prendida.

        Contesta la pregunta que hace que alguien apague una herramienta de
        seguridad: "¿esto me está comiendo la máquina?". Mejor que la conteste
        el panel a que la conteste el Administrador de tareas.
        """
        datos = sistema.snapshot() if datos is None else datos
        if not datos.get("disponible"):
            return (f"<p class='warn'>No puedo mostrar el estado de la máquina: "
                    f"{html_lib.escape(datos.get('aviso', ''))}</p>")

        def medidor(titulo: str, pct, detalle: str, color: str | None = None) -> str:
            if pct is None:
                return ""
            # Verde hasta 70, ámbar hasta 90, rojo arriba. Los umbrales están
            # acá y no en cada llamada para que las tres barras signifiquen lo
            # mismo: una roja tiene que querer decir lo mismo en las tres.
            color = color or ("#7bd88f" if pct < 70 else
                              "#e0b341" if pct < 90 else "#ff8a8a")
            return (f"<div class='medidor'><div class='medidor-cab'>"
                    f"<span>{titulo}</span><span>{pct}%</span></div>"
                    f"<div class='barra'><i style='width:{min(100, pct)}%;"
                    f"background:{color}'></i></div>"
                    f"<div class='medidor-pie'>{html_lib.escape(detalle)}</div></div>")

        libre_gb = datos.get("disco_libre_gb")
        detalle_disco = (
            f"{datos.get('disco_usado_gb', 0)} de {datos.get('disco_total_gb', 0)} GB"
            + (f" · {libre_gb} GB libres" if libre_gb is not None else "")
        )
        partes = [
            medidor("CPU", datos.get("cpu_pct"),
                    f"{datos.get('cpu_nucleos', 0)} núcleos"),
            medidor("Memoria", datos.get("ram_pct"),
                    f"{datos.get('ram_usada_gb', 0)} de {datos.get('ram_total_gb', 0)} GB"),
            medidor("Disco", datos.get("disco_pct"), detalle_disco,
                    sistema.color_de_disco(datos.get("disco_pct"), libre_gb)
                    if datos.get("disco_pct") is not None else None),
        ]
        extra = [f"{html_lib.escape(datos.get('sistema', ''))}"]
        if datos.get("encendida_hace"):
            extra.append(f"prendida hace {datos['encendida_hace']}")
        if datos.get("temperatura") is not None:
            extra.append(f"{datos['temperatura']} °C")
        aviso_disco = ""
        if datos.get("disco_pct") is not None and datos["disco_pct"] >= 90:
            queda = f" Quedan {libre_gb} GB libres." if libre_gb is not None else ""
            critico = sistema.color_de_disco(datos["disco_pct"], libre_gb) == "#ff8a8a"
            titulo = "Disco casi lleno." if critico else "Uso de disco alto."
            clase = "warn aviso-disco critico" if critico else "aviso-disco"
            aviso_disco = (
                f"<p class='{clase}'><b>{titulo}</b>" + queda
                + " Revisá la pestaña Diagnóstico antes de que las bases de datos "
                  "se queden sin espacio.</p>"
            )
        return (f"<div class='medidores'>{''.join(p for p in partes if p)}</div>"
                f"<p class='subtitle' style='margin:0.2rem 0 0'>"
                f"{' &middot; '.join(extra)}</p>{aviso_disco}")

    def _globalbar(self, health: dict, operacion_en_curso: bool = False) -> str:
        """Acciones globales posibles ahora; PÁNICO queda aislado a propósito."""
        if operacion_en_curso:
            acciones = ("<button type='button' disabled aria-disabled='true'>"
                        "Operación en curso…</button>")
        else:
            core_vivo = any(
                health.get(s.key, APAGADO) != APAGADO
                for s in PROJECT_SPECS if s.key != "vpn"
            )
            vpn_viva = health.get("vpn", APAGADO) != APAGADO
            botones = []
            if not core_vivo:
                botones.append(
                    "<form method='post' action='/start-core' "
                    "onsubmit=\"return confirm('¿Encender el núcleo y dejarlo con inicio automático?')\">"
                    "<button class='ok-btn' type='submit'>Encender núcleo</button></form>"
                )
            if vpn_viva:
                botones.append(
                    "<form method='post' action='/stop-vpn' "
                    "onsubmit=\"return confirm('¿Apagar solo la VPN?')\">"
                    "<button type='submit'>Apagar VPN</button></form>"
                )
            else:
                botones.append(
                    "<form method='post' action='/start-vpn' "
                    "onsubmit=\"return confirm('¿Encender la VPN? Levanta laboratorio, "
                    "aprovisiona y conecta (1-3 min).')\">"
                    "<button type='submit'>Encender VPN (todo en uno)</button></form>"
                )
            if core_vivo or vpn_viva:
                botones.append(
                    "<form method='post' action='/stop-all' "
                    "onsubmit=\"return confirm('¿Apagar TODO? Detiene núcleo y VPN y "
                    "elimina sus inicios automáticos.')\">"
                    "<button class='danger-btn' type='submit'>Apagar todo</button></form>"
                )
            acciones = "".join(botones)

        panic = (
            "<div class='emergencybar'><span><b>Emergencia</b><small>Restaura Internet "
            "y detiene toda la suite.</small></span>"
            "<form method='post' action='/panic' "
            "onsubmit=\"return confirm('PÁNICO: intenta restaurar Internet, desconecta "
            "la VPN, detiene todos los servicios y elimina sus inicios automáticos. "
            "Puede interrumpir protección y conexiones. ¿Confirmás?')\">"
            "<button class='panic-btn' type='submit'>PÁNICO</button></form></div>"
        )
        return f"<div class='globalbar'>{acciones}</div>{panic}"

    def _bloque_contadores(self, projects) -> str:
        """Qué pasó hoy, sumando las cinco bases.

        Cada proyecto ya muestra sus propias estadísticas con más detalle.
        Lo único que SecureCenter puede decir y ninguno de ellos puede es
        cuánto pasó en total y en qué capa.
        """
        contadores = resumen.construir(projects)
        total = resumen.total_de_hoy(contadores)
        lo_de_ayer = resumen.ayer(projects)

        if total is None:
            cabeza = ("<div class='hoy'><div class='hoy-num'>-</div>"
                      "<div class='label'>Sin datos todavía. ¿Los proyectos "
                      "corrieron alguna vez?</div></div>")
        else:
            if lo_de_ayer is None:
                comparacion = "primer día con datos"
            elif lo_de_ayer == total:
                comparacion = "igual que ayer"
            else:
                # La comparación con ayer es lo que convierte un número suelto
                # en información. "126" no dice nada; "126, ayer 40" sí.
                flecha = "&#9650;" if total > lo_de_ayer else "&#9660;"
                comparacion = f"{flecha} ayer fueron {sistema.miles(lo_de_ayer)}"
            cabeza = (f"<div class='hoy'><div class='hoy-num'>{sistema.miles(total)}</div>"
                      f"<div class='label'>eventos de seguridad hoy<br>"
                      f"<span style='font-size:0.8rem'>{comparacion}</span></div></div>")

        tarjetas = "".join(
            f"<div class='card' title='{html_lib.escape(c['ayuda'])}'>"
            f"<div class='value'>{'-' if c['valor'] is None else sistema.miles(c['valor'])}</div>"
            f"<div class='label'>{html_lib.escape(c['titulo'])}"
            + ("<br><span style='font-size:0.75rem'>hoy</span>" if c["de_hoy"] else "")
            + "</div></div>"
            for c in contadores
        )
        return cabeza + f"<div class='stats'>{tarjetas}</div>"

    def _serve_eventos(self) -> None:
        """Canal de eventos (SSE): la respuesta queda abierta y se mandan los
        fragmentos cuando cambian.

        Reemplaza al `<meta refresh>` de cada 5 segundos. El problema de aquel
        no era la frecuencia sino que recargaba la página entera: volvía a la
        primera pestaña, reseteaba el scroll y mandaba la consola al principio
        justo mientras estabas leyendo un encendido que tardaba minutos.

        SSE y no WebSockets porque esto va en UNA sola dirección (el servidor
        avisa, el navegador muestra), y para eso alcanza HTTP común, sin
        handshake ni dependencias nuevas. Es lo mismo que ya usan los paneles
        de SecureProxy, SecureDNS y SecureHIPS.
        """
        base = DashboardRequestHandler
        with base._sse_lock:
            if base._sse_clientes >= self.MAX_CLIENTES_SSE:
                self.send_error(503, "demasiadas pestañas abiertas")
                return
            base._sse_clientes += 1
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            ultima = None
            latido = 0
            while True:
                datos = self._fragmentos()
                if datos["revision"] != ultima:
                    ultima = datos["revision"]
                    self.wfile.write(
                        f"data: {json.dumps(datos, ensure_ascii=False)}\n\n".encode("utf-8")
                    )
                    self.wfile.flush()
                    latido = 0
                else:
                    latido += 1
                    # Un comentario cada ~15 s mantiene viva la conexión y, si
                    # la pestaña ya se cerró, es lo que lo detecta: falla el
                    # write y el hilo termina en vez de quedar colgado.
                    if latido >= 5:
                        self.wfile.write(b": latido\n\n")
                        self.wfile.flush()
                        latido = 0
                time.sleep(3)
        except (BrokenPipeError, ConnectionResetError, OSError, ValueError):
            pass
        finally:
            with base._sse_lock:
                base._sse_clientes -= 1

    def _serve_dashboard(self) -> None:
        frag = self._fragmentos()
        cards = frag["cards"]
        maquina = frag["maquina"]
        contadores = frag["contadores"]
        globalbar = frag["globalbar"]
        lista_alertas = frag["alertas"]
        chapa = frag["chapa"]
        lista_incidentes = frag["incidentes"]
        chapa_inc = frag["chapa_inc"]
        opciones_proyecto = frag["opciones_proyecto"]
        opciones_tipo = frag["opciones_tipo"]
        bloque_diagnostico = frag["diagnostico"]
        bloque_agentes = frag["agentes"]
        # Los reportes NO van por el canal de eventos: la lista de copias
        # cambia solo cuando apretás un botón, y recorrer la carpeta en cada
        # repintado sería tocar el disco por nada.
        bloque_reportes = self._bloque_reportes()
        bloque_rendimiento = self._bloque_rendimiento()
        last_line = frag["consola"]
        sections = frag["secciones"]
        rows = frag["timeline"]
        warn = frag["aviso"]

        page = f"""<!DOCTYPE html><html lang="es"><head>
<meta charset="utf-8">
<title>SecureCenter</title>
<style>
  * {{ box-sizing:border-box; }}
  body {{ font-family:-apple-system,"Segoe UI",sans-serif; background:#0f1115; color:#e6e6e6; padding:2rem; max-width:1000px; margin:0 auto; }}
  h1 {{ font-size:1.5rem; margin-bottom:0.25rem; }}
  h2 {{ font-size:1.05rem; }}
  .subtitle {{ color:#b0b6c2; font-size:0.9rem; margin-top:0; }}
  .stats {{ display:flex; gap:1rem; margin:1.25rem 0; flex-wrap:wrap; }}
  .medidores {{ display:flex; gap:1.5rem; flex-wrap:wrap; margin:1rem 0 0; }}
  .medidor {{ flex:1; min-width:180px; }}
  .medidor-cab {{ display:flex; justify-content:space-between; font-size:0.85rem; }}
  .medidor-pie {{ color:#b0b6c2; font-size:0.82rem; margin-top:0.2rem; }}
  .barra {{ background:#242832; border-radius:4px; height:7px; margin-top:0.3rem; overflow:hidden; }}
  .barra i {{ display:block; height:100%; border-radius:4px; }}
  .hoy {{ display:flex; align-items:center; gap:1rem; margin:1.5rem 0 0; }}
  .hoy-num {{ font-size:2.6rem; font-weight:600; line-height:1; }}
  .ficha {{ display:flex; gap:1.4rem; flex-wrap:wrap; border-top:1px solid #2a2e37;
            margin-top:0.7rem; padding-top:0.7rem; }}
  .dato {{ display:flex; flex-direction:column; }}
  .dato-k {{ color:#b0b6c2; font-size:0.76rem; text-transform:uppercase; letter-spacing:0.04em; }}
  .dato-v {{ font-family:Consolas,"Courier New",monospace; font-size:0.9rem; }}
  .filtros {{ display:flex; gap:0.6rem; flex-wrap:wrap; align-items:center; margin:0.8rem 0; }}
  .filtros input, .filtros select {{ background:#1a1d24; color:#e6e6e6;
      border:1px solid #2a2e37; border-radius:7px; padding:0.42rem 0.6rem; font-size:0.9rem; }}
  .filtros input {{ min-width:16rem; }}
  .alerta {{ background:#141720; border:1px solid #2a2e37; border-left:3px solid #2a2e37;
      border-radius:9px; padding:0.8rem 1rem; margin:0.6rem 0; }}
  .alerta-cab {{ display:flex; align-items:center; gap:0.4rem; flex-wrap:wrap; }}
  .alerta-botones {{ display:flex; gap:0.4rem; margin-top:0.6rem; flex-wrap:wrap; }}
  .arreglo {{ color:#8fb8e8; font-size:0.85rem; margin-top:0.3rem; }}
  .boton-link {{ display:inline-block; background:#1f2430; border:1px solid #2a2e37;
      color:#e6e6e6; padding:0.32rem 0.7rem; border-radius:7px; text-decoration:none;
      font-size:0.85rem; }}
  .chapa {{ background:#8a2f2f; color:#fff; border-radius:9px; padding:0 0.4rem;
      font-size:0.72rem; margin-left:0.25rem; }}
  .chip {{ padding:0.1rem 0.5rem; border-radius:6px; font-size:0.78rem; }}
  .chip.ok {{ background:#1d3527; color:#7bd88f; }}
  .chip.aviso {{ background:#3a3320; color:#e3b341; }}
  .chip.mal {{ background:#3a2020; color:#ff8a8a; }}
  .chip.na {{ background:#22262e; color:#9aa0a6; }}
  p.bien {{ color:#7bd88f; }}
  .graficos {{ display:flex; gap:1.2rem; flex-wrap:wrap; margin-top:0.8rem; }}
  .grafico {{ flex:1; min-width:260px; background:#141720; border:1px solid #2a2e37;
              border-radius:9px; padding:0.8rem 0.9rem; }}
  .grafico-cab {{ display:flex; justify-content:space-between; font-size:0.9rem; }}
  .grafico-pie {{ color:#9aa0a6; font-size:0.75rem; margin-top:0.3rem; }}
  .svg-serie {{ width:100%; height:80px; display:block; margin-top:0.4rem; }}
  .card {{ background:#1a1d24; border-radius:8px; padding:0.9rem 1.3rem; min-width:150px; }}
  .card .label {{ color:#b0b6c2; font-size:0.92rem; }}
  .globalbar {{ display:flex; gap:0.5rem; flex-wrap:wrap; margin:1rem 0 0.5rem; }}
  .emergencybar {{ display:flex; justify-content:space-between; align-items:center; gap:1rem;
      border:1px solid #6b292d; background:#241416; border-radius:8px; padding:0.7rem 0.8rem;
      margin:0.75rem 0 0.5rem; }}
  .emergencybar span {{ display:flex; flex-direction:column; color:#ffb3b3; }}
  .emergencybar small {{ color:#c99b9e; margin-top:0.15rem; }}
  button.panic-btn {{ background:#a92932; color:#fff; font-weight:700; }}
  button:disabled {{ cursor:not-allowed; opacity:0.55; }}
  .aviso-disco {{ color:#e0b341; background:#272313; border:1px solid #5a4d20;
      border-radius:7px; padding:0.55rem 0.75rem; margin:0.6rem 0 0; }}
  .aviso-disco.critico {{ color:#ff8a8a; background:#2a1618; border-color:#5b292d; }}
  .project {{ background:#141720; border:1px solid #2a2e37; border-radius:10px; padding:1rem 1.25rem; margin:1rem 0; }}
  .project .head {{ display:flex; justify-content:space-between; align-items:center; }}
  .project .head h2 {{ display:flex; align-items:center; gap:0.5rem; margin:0.3rem 0; }}
  /* El agarradero para reordenar. Son dos columnas de tres puntos hechas con
     el caracter de puntos suspensivos vertical, sin imagenes ni iconos
     externos: el panel tiene que seguir funcionando sin internet. */
  .agarradero {{ cursor:grab; color:#5a616e; font-size:1.1rem; letter-spacing:-3px;
                 user-select:none; padding:0 0.15rem; }}
  .agarradero:hover {{ color:#9aa0a6; }}
  .agarradero:active {{ cursor:grabbing; }}
  /* La tarjeta que se esta arrastrando y el lugar donde va a caer. */
  .project.arrastrando {{ opacity:0.4; }}
  .project.destino {{ border-color:#7fb2ff; }}
  table {{ width:100%; border-collapse:collapse; margin-top:0.5rem; }}
  th,td {{ text-align:left; padding:0.45rem 0.7rem; border-bottom:1px solid #2a2e37; font-size:0.82rem; }}
  th {{ color:#9aa0a6; font-weight:500; }}
  a {{ color:#7fb2ff; }}
  .warn {{ color:#ff8a8a; font-size:0.85rem; }}
  /* La fecha en una sola linea: sin esto, "04/08/2026 01:27:32" se parte en
     dos renglones cuando la columna se angosta y la tabla queda ilegible. */
  td.fecha {{ white-space:nowrap; }}
  .resultado {{ border-radius:8px; padding:0.7rem 1rem; margin:0.75rem 0; font-size:0.85rem; }}
  .resultado ul {{ margin:0.4rem 0 0; padding-left:1.2rem; }}
  /* En curso: ámbar, el mismo color que "sin conectar", para que se lea como
     "esto todavía no terminó" y no como éxito ni como error. */
  .resultado.run {{ background:#2a2411; border:1px solid #3d3316; color:#e6d08a; }}
  .resultado.ok {{ background:#16241a; border:1px solid #1e3a26; color:#b7e3c2; }}
  .resultado.err {{ background:#2a1618; border:1px solid #3a1f22; color:#ffb3b3; }}
  /* La consola propiamente dicha: monoespaciada, con alto máximo y scroll
     propio, para que un encendido largo no empuje el resto de la página
     hasta el infinito. */
  .consola {{ margin:0.5rem 0 0; max-height:16rem; overflow-y:auto; white-space:pre-wrap;
             word-break:break-word; font-family:Consolas,"Courier New",monospace;
             font-size:0.8rem; line-height:1.45; background:#00000033;
             border-radius:6px; padding:0.5rem 0.7rem; }}
  button {{ background:#2a2e37; border:none; color:#e6e6e6; border-radius:6px; padding:0.5rem 1rem; cursor:pointer; font-size:0.9rem; }}
  button.ok-btn {{ background:#1e3a26; color:#7bd88f; }}
  button.danger-btn {{ background:#3a1f22; color:#ff8a8a; }}
  .tabs {{ display:flex; gap:0.5rem; margin-top:1.5rem; border-bottom:1px solid #2a2e37; }}
  /* Las pestañas son <button>, así que heredaban el border-radius de la
     regla de arriba y la línea azul del subrayado salía curvada en las
     puntas. Se lo sacamos explícitamente: acá la línea tiene que ser recta,
     de lado a lado, como en los dashboards de SecureProxy y SecureDNS. */
  .tab-btn {{ background:none; border:none; border-radius:0; color:#9aa0a6; padding:0.6rem 1rem; cursor:pointer; font-size:0.85rem; font-family:inherit; border-bottom:2px solid transparent; }}
  .tab-btn.active {{ color:#e6e6e6; border-bottom:2px solid #7fb2ff; }}
  .tab-panel {{ display:none; padding-top:1rem; }}
  .tab-panel.active {{ display:block; }}
  form {{ display:inline; }}
</style></head><body>
  <h1>SecureCenter</h1>
  <p class="subtitle">Centro de control del stack - <span id="estado">en vivo</span></p>
  <div id="aviso">{warn}</div><div id="consola-bloque">{last_line}</div>
  <div id="maquina">{maquina}</div>
  <div id="contadores">{contadores}</div>
  <div class="stats" id="tarjetas">{cards}</div>

  <div id="acciones-globales">{globalbar}</div>

  <div class="tabs">
    <button class="tab-btn active" data-tab="servicios" onclick="showTab('servicios',this)">Servicios</button>
    <button class="tab-btn" data-tab="agentes" onclick="showTab('agentes',this)">Agentes</button>
    <button class="tab-btn" data-tab="timeline" onclick="showTab('timeline',this)">Línea de tiempo</button>
    <button class="tab-btn" data-tab="alertas" onclick="showTab('alertas',this)">Alertas <span id="chapa-alertas">{chapa}</span></button>
    <button class="tab-btn" data-tab="incidentes" onclick="showTab('incidentes',this)">Incidentes <span id="chapa-incidentes">{chapa_inc}</span></button>
    <button class="tab-btn" data-tab="diagnostico" onclick="showTab('diagnostico',this)">Diagnóstico</button>
    <button class="tab-btn" data-tab="reportes" onclick="showTab('reportes',this)">Reportes</button>
    <button class="tab-btn" data-tab="rendimiento" onclick="showTab('rendimiento',this)">Rendimiento</button>
  </div>

  <div id="tab-servicios" class="tab-panel active">
    <div id="secciones">{sections}</div>
  </div>

  <div id="tab-agentes" class="tab-panel">
    <h2>Equipos vigilados por Secure-Agent</h2>
    <div id="agentes">{bloque_agentes}</div>
  </div>

  <div id="tab-timeline" class="tab-panel">
    <h2>Eventos de seguridad, por hora</h2>
    <!-- Los filtros son de navegador, no de servidor. Con 60 filas en
         pantalla, escribir en el buscador y esperar una vuelta al servidor
         seria peor: asi filtra mientras escribis y sigue andando aunque el
         canal de eventos se caiga. -->
    <div class="filtros">
      <input id="f-texto" type="search" placeholder="buscar dominio, IP o texto..."
             oninput="filtrar()" autocomplete="off">
      <select id="f-proyecto" onchange="filtrar()">
        <option value="">todos los proyectos</option>{opciones_proyecto}
      </select>
      <select id="f-tipo" onchange="filtrar()">
        <option value="">todo lo que pasó</option>{opciones_tipo}
      </select>
      <select id="f-cuando" onchange="filtrar()">
        <option value="">cualquier momento</option>
        <option value="1">última hora</option>
        <option value="24">último día</option>
      </select>
      <span id="f-cuenta" class="subtitle"></span>
    </div>
    <table><tr><th>Fecha y hora</th><th>Proyecto</th><th>Tipo</th><th>Detalle</th></tr>
    <tbody id="timeline">{rows}</tbody></table>
  </div>

  <div id="tab-incidentes" class="tab-panel">
    <h2>Historias que cruzan dos o más herramientas</h2>
    <p class="subtitle" style="margin-top:0">
      Cada herramienta ve una parte. Un incidente es lo que ninguna puede
      contestar sobre sí misma. <b>Esto no bloquea nada</b>: arma la historia
      y la muestra; quién decide sigue siendo cada herramienta, y quién aplica
      en el firewall sigue siendo SecureHIPS.
    </p>
    <div id="incidentes">{lista_incidentes}</div>
  </div>

  <div id="tab-alertas" class="tab-panel">
    <h2>Lo que necesita que hagas algo</h2>
    <p class="subtitle" style="margin-top:0">
      La línea de tiempo dice qué pasó. Esto dice qué hay que atender: son
      condiciones que <b>siguen siendo ciertas</b> ahora mismo, no cosas que
      pasaron una vez.
    </p>
    <div id="alertas">{lista_alertas}</div>
  </div>

  <div id="tab-reportes" class="tab-panel">{bloque_reportes}</div>

  <div id="tab-rendimiento" class="tab-panel">{bloque_rendimiento}</div>

  <div id="tab-diagnostico" class="tab-panel">
    <h2>Revisión completa</h2>
    <p class="subtitle" style="margin-top:0">
      Toca la red, así que no corre solo: se hace cuando lo pedís.
    </p>
    <form method="post" action="/diagnostico">
      <button class="ok-btn" type="submit">Revisar todo ahora</button>
    </form>
    <div id="diagnostico">{bloque_diagnostico}</div>
  </div>

<script>
var K='securecenter_tab';
/* Filtro de la linea de tiempo, del lado del navegador.
   Con 60 filas en pantalla, ir al servidor por cada tecla seria mas lento y
   dejaria de andar si el canal de eventos se cae. */
function filtrar(){{
  var txt=(document.getElementById('f-texto').value||'').toLowerCase();
  var proy=document.getElementById('f-proyecto').value;
  var tipo=document.getElementById('f-tipo').value;
  var horas=parseFloat(document.getElementById('f-cuando').value||'0');
  var corte=horas?(Date.now()/1000-horas*3600):0;
  var filas=document.querySelectorAll('#timeline tr');
  var visibles=0;
  filas.forEach(function(f){{
    if(!f.dataset.proyecto){{f.style.display='';return;}}
    var ok=true;
    if(proy&&f.dataset.proyecto!==proy)ok=false;
    if(ok&&tipo&&f.dataset.tipo!==tipo)ok=false;
    if(ok&&corte&&parseFloat(f.dataset.epoch||'0')<corte)ok=false;
    if(ok&&txt&&f.textContent.toLowerCase().indexOf(txt)===-1)ok=false;
    f.style.display=ok?'':'none';
    if(ok)visibles++;
  }});
  var c=document.getElementById('f-cuenta');
  if(c)c.textContent=visibles+' de '+filas.length;
}}
function showTab(n,b){{document.querySelectorAll('.tab-panel').forEach(function(e){{e.classList.remove('active');}});document.querySelectorAll('.tab-btn').forEach(function(e){{e.classList.remove('active');}});document.getElementById('tab-'+n).classList.add('active');b.classList.add('active');try{{localStorage.setItem(K,n);}}catch(e){{}}}}
(function(){{var s=null;try{{s=localStorage.getItem(K);}}catch(e){{}}if(s){{var b=document.querySelector('.tab-btn[data-tab="'+s+'"]');if(b)showTab(s,b);}}}})();
/* La consola arranca mostrando el final, como una terminal de verdad. */
function alFinal(){{var c=document.getElementById('consola');if(c)c.scrollTop=c.scrollHeight;}}
alFinal();

/* Actualizacion en vivo por SSE, en lugar del <meta refresh> de cada 5s que
   habia antes. Aquel recargaba la pagina entera: volvia a la primera
   pestania, reseteaba el scroll y mandaba la consola al principio justo
   mientras estabas leyendo un encendido de varios minutos. */
(function(){{
  var estado=document.getElementById('estado');
  function volverAlRefresco(){{
    if(estado)estado.textContent='se actualiza cada 5 segundos';
    setTimeout(function(){{location.reload();}},5000);
  }}
  if(!window.EventSource){{volverAlRefresco();return;}}
  function pintar(id,html){{
    var n=document.getElementById(id);
    /* Solo se toca el DOM si cambio: si no, se pierde la seleccion de texto
       y parpadea sin motivo. */
    if(n&&n.innerHTML!==html)n.innerHTML=html;
  }}
  var fuente=new EventSource('/eventos');
  window.fuenteDeEventos=fuente;
  var fallas=0;
  fuente.onmessage=function(ev){{
    fallas=0;
    if(estado)estado.textContent='en vivo';
    var d=JSON.parse(ev.data);
    pintar('aviso',d.aviso);
    pintar('maquina',d.maquina);
    pintar('contadores',d.contadores);
    pintar('acciones-globales',d.globalbar);
    pintar('alertas',d.alertas);
    pintar('chapa-alertas',d.chapa);
    pintar('incidentes',d.incidentes);
    pintar('chapa-incidentes',d.chapa_inc);
    pintar('diagnostico',d.diagnostico);
    pintar('agentes',d.agentes);
    pintar('tarjetas',d.cards);
    var antes=document.getElementById('secciones');
    if(antes&&antes.innerHTML!==d.secciones){{
      antes.innerHTML=d.secciones;
      /* El canal reemplaza las secciones enteras, asi que hay que volver a
         acomodarlas como las dejaste. Sin esto, el orden que elegiste se
         perderia solo a los pocos segundos. */
      if(window.aplicarOrdenGuardado)window.aplicarOrdenGuardado();
    }}
    pintar('timeline',d.timeline);
    /* El canal reemplaza la tabla entera: sin esto, el filtro
       que escribiste se perderia solo a los pocos segundos. */
    if(document.getElementById('f-texto'))filtrar();
    var c=document.getElementById('consola-bloque');
    if(c&&c.innerHTML!==d.consola){{c.innerHTML=d.consola;alFinal();}}
  }};
  fuente.onerror=function(){{
    /* EventSource reconecta solo. Recien si insiste en fallar se vuelve al
       refresco clasico, para no quedar con una pagina congelada. */
    if(estado)estado.textContent='reconectando...';
    fallas+=1;
    if(fallas>=3){{fuente.close();volverAlRefresco();}}
  }};
}})();

/* ------------------------------------------------------------------
   Reordenar las tarjetas arrastrando el agarradero.

   El orden se guarda en localStorage y se vuelve a aplicar despues de CADA
   actualizacion por SSE. Eso ultimo no es un detalle: el canal de eventos
   reemplaza el HTML de las secciones enteras, asi que sin reaplicar, el
   orden que elegiste se perderia solo a los pocos segundos y pareceria que
   no se guardo nada.

   Se escucha en el contenedor y no en cada tarjeta (delegacion), por el
   mismo motivo: las tarjetas se destruyen y se vuelven a crear, y los
   listeners puestos sobre ellas se irian con ellas.
   ------------------------------------------------------------------ */
(function(){{
  var CLAVE_ORDEN='securecenter_orden';
  var cont=document.getElementById('secciones');
  if(!cont)return;
  var arrastrando=null;

  function leerOrden(){{
    try{{var g=localStorage.getItem(CLAVE_ORDEN);return g?JSON.parse(g):null;}}
    catch(e){{return null;}}
  }}
  function guardarOrden(){{
    var claves=[];
    cont.querySelectorAll('.project').forEach(function(p){{
      claves.push(p.getAttribute('data-proyecto'));
    }});
    try{{localStorage.setItem(CLAVE_ORDEN,JSON.stringify(claves));}}catch(e){{}}
  }}
  function aplicarOrden(){{
    var orden=leerOrden();
    if(!orden)return;
    orden.forEach(function(clave){{
      var p=cont.querySelector('.project[data-proyecto="'+clave+'"]');
      /* appendChild sobre un nodo que ya esta en el DOM lo MUEVE al final.
         Recorriendo el orden guardado de principio a fin, cada uno se va
         acomodando detras del anterior. Los proyectos que no esten en el
         orden guardado (uno nuevo) quedan primeros, que es lo que se quiere:
         algo que aparecio recien conviene que se vea. */
      if(p)cont.appendChild(p);
    }});
  }}
  window.aplicarOrdenGuardado=aplicarOrden;
  aplicarOrden();

  cont.addEventListener('dragstart',function(ev){{
    var agarre=ev.target.closest?ev.target.closest('.agarradero'):null;
    if(!agarre){{ev.preventDefault();return;}}
    arrastrando=agarre.closest('.project');
    if(!arrastrando)return;
    arrastrando.classList.add('arrastrando');
    ev.dataTransfer.effectAllowed='move';
    /* Firefox no dispara el drag si no se setea algo en dataTransfer. */
    try{{ev.dataTransfer.setData('text/plain','');}}catch(e){{}}
  }});

  cont.addEventListener('dragover',function(ev){{
    if(!arrastrando)return;
    ev.preventDefault();
    var sobre=ev.target.closest?ev.target.closest('.project'):null;
    if(!sobre||sobre===arrastrando)return;
    cont.querySelectorAll('.project.destino').forEach(function(p){{
      p.classList.remove('destino');
    }});
    sobre.classList.add('destino');
    /* Se compara con la MITAD de la tarjeta de destino para decidir si va
       antes o despues. Sin eso, arrastrar hacia abajo se siente al reves. */
    var caja=sobre.getBoundingClientRect();
    var mitad=caja.top+caja.height/2;
    if(ev.clientY<mitad)cont.insertBefore(arrastrando,sobre);
    else cont.insertBefore(arrastrando,sobre.nextSibling);
  }});

  function terminar(){{
    if(!arrastrando)return;
    arrastrando.classList.remove('arrastrando');
    cont.querySelectorAll('.project.destino').forEach(function(p){{
      p.classList.remove('destino');
    }});
    arrastrando=null;
    guardarOrden();
  }}
  cont.addEventListener('drop',function(ev){{ev.preventDefault();terminar();}});
  cont.addEventListener('dragend',terminar);
}})();
</script>
</body></html>"""
        body = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _project_section(
        self, spec, projects, estado_key: str, operacion_en_curso: bool = False
    ) -> str:
        project = projects[spec.key]
        # `.get` y no `[...]`: con corchetes, agregar un proyecto nuevo a
        # PROJECT_SPECS y olvidarse de esta tabla tira el panel entero con un
        # KeyError. Pasó agregando Secure-Scanner. Sin puerto, la tarjeta se
        # muestra igual y solo se queda sin el link a su panel.
        port = {
            "proxy": self.orchestrator.cfg.ports.proxy_dashboard,
            "dns": self.orchestrator.cfg.ports.dns_dashboard,
            "vpn": self.orchestrator.cfg.ports.vpn_dashboard,
            "hips": self.orchestrator.cfg.ports.hips_dashboard,
            "intel": self.orchestrator.cfg.ports.intel_dashboard,
            "scanner": self.orchestrator.cfg.ports.scanner_dashboard,
            # El de INGESTA, que es el que dice si está vivo y el que se
            # libera al apagarlo. Antes acá figuraba el 8896, que es un panel
            # que Secure-Agent no tiene: la tarjeta mostraba un puerto donde
            # no escucha nadie, así que decía "apagado" incluso arrancado.
            "agente": self.orchestrator.cfg.ports.agente_ingesta,
        }.get(spec.key)
        alive = estado_key != APAGADO
        estado, color = {
            ACTIVO: ("operativo", "#7bd88f"),
            PARCIAL: ("degradado", "#e0b341"),
            APAGADO: ("detenido", "#9aa0a6"),
        }.get(estado_key, ("detenido", "#9aa0a6"))
        if not project.found:
            estado, color = "no disponible", "#9aa0a6"
            body = "<p class='warn'>No encontrado en el disco (revisá config/config.yaml).</p>"
        else:
            if spec.dashboard_path is None:
                # No tiene panel propio, y decirlo es mejor que ofrecer un link
                # que da 405. Ver el comentario de Secure-Agent en projects.py.
                link = ("<span class='subtitle'>este es el servidor receptor; "
                        "la telemetría recibida alimenta la detección de incidentes</span>")
            elif port is None:
                link = ""
            elif alive:
                link = (f"<a href='http://127.0.0.1:{port}{spec.dashboard_path}' "
                        f"target='_blank'>abrir su dashboard &#8599;</a>")
            else:
                link = ("<span style='color:#9aa0a6'>su dashboard abre cuando "
                        "está corriendo</span>")
            start_label = (
                f"Encender {spec.display_name} (todo en uno)"
                if spec.key == "vpn"
                else f"Encender {spec.display_name}"
            )
            stop_label = f"Apagar {spec.display_name}"
            disabled = (
                " disabled aria-disabled='true' title='Hay una operación en curso'"
                if operacion_en_curso else ""
            )
            # Ojo: el parámetro va en un input OCULTO, no en la URL del action.
            # Un formulario GET de HTML descarta la query string del action y la
            # reemplaza por sus propios campos; por eso '/stop-one?p=proxy' no
            # mandaba nunca el p y el botón "no hacía nada".
            if alive:
                controles = (
                    f"<form method='post' action='/stop-one' "
                    f"onsubmit=\"return confirm('¿Seguro que querés apagar {spec.display_name}?')\">"
                    f"<input type='hidden' name='p' value='{spec.key}'>"
                    f"<button class='danger-btn' type='submit'{disabled}>{stop_label}</button></form>"
                    f"<form method='post' action='/restart-one' "
                    f"onsubmit=\"return confirm('¿Reiniciar {spec.display_name}? "
                    f"Se apaga y se vuelve a encender.')\">"
                    f"<input type='hidden' name='p' value='{spec.key}'>"
                    f"<button type='submit'{disabled}>Reiniciar</button></form>"
                )
            else:
                controles = (
                    f"<form method='post' action='/start-one'>"
                    f"<input type='hidden' name='p' value='{spec.key}'>"
                    f"<button class='ok-btn' type='submit'{disabled}>{start_label}</button></form>"
                )
            body = (
                "<div style='margin:0.5rem 0; display:flex; gap:0.5rem; "
                f"align-items:center; flex-wrap:wrap'>{controles}<span>{link}</span></div>"
                + self._ficha(spec, port, estado_key)
            )
        # `data-proyecto` es lo que le permite al JavaScript guardar el orden
        # en que los dejaste. El agarradero (los seis puntos) es lo ÚNICO
        # arrastrable: si lo fuera la tarjeta entera, seleccionar texto o
        # apretar un botón empezaría a arrastrar sin querer.
        return (
            f"<div class='project' data-proyecto='{spec.key}'><div class='head'>"
            f"<h2><span class='agarradero' draggable='true' "
            f"title='Arrastrá para cambiar el orden'>&#8942;&#8942;</span>"
            f"{spec.display_name} <span style='font-size:0.8rem;color:#9aa0a6'>· {spec.role}</span></h2>"
            f"<span style='color:{color}'>&#9679; {estado}</span></div>{body}</div>"
        )


def build_dashboard_server(host, port, orchestrator, logger_db) -> ThreadingHTTPServer:
    handler = type(
        "InjectedHandler", (DashboardRequestHandler,),
        {"orchestrator": orchestrator, "logger_db": logger_db},
    )
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server
