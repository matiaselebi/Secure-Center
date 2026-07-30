"""Dashboard unificado de SecureCenter (puerto 8899).

Mismo estilo oscuro que los tres proyectos. Estructura:
- Barra global arriba: salud de los tres + botones globales (Encender núcleo,
  Encender VPN, Apagar todo, Pánico).
- Tres apartados, uno por proyecto: su estado, sus botones de iniciar/parar
  ese servicio solo, y sus últimos eventos.
- Pestaña "Línea de tiempo": los eventos de los tres, mezclados por hora.

Las operaciones largas (aprovisionar la VPN, encender el núcleo) corren en un
hilo aparte, de a una por vez, para no colgar la página. Su salida se ve EN
VIVO en la consola de arriba, línea por línea a medida que ocurre (la página
se refresca sola cada 5 segundos), y al terminar ese mismo bloque queda verde
si salió bien o rojo si falló. La línea de tiempo no cambia: sigue siendo el
registro histórico de los tres proyectos.
"""

import html as html_lib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .health import ACTIVO, APAGADO, PARCIAL, state_snapshot
from .logger_db import LoggerDB
from .logs import collect_logs
from .orchestrator import Orchestrator
from .projects import PROJECT_SPECS


class DashboardRequestHandler(BaseHTTPRequestHandler):
    orchestrator: Orchestrator
    logger_db: LoggerDB

    _bg_lock = threading.Lock()
    _bg_running: str | None = None
    # Resultado de la última operación, para mostrarlo arriba del dashboard.
    # Sin esto, apretar un botón que falla "parece que no hace nada".
    _last_result: tuple[str, bool, list[str]] | None = None
    # Salida en vivo de la operación en curso: se va llenando mientras corre.
    _live_lines: list[str] = []

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        pass

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        path = parsed.path.rstrip("/")
        if path == "/health":
            return self._plain("ok")
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
            return self._individual(parsed.query, start=True)
        if path == "/stop-one":
            return self._individual(parsed.query, start=False)
        self._serve_dashboard()

    def _individual(self, query: str, start: bool) -> None:
        key = (parse_qs(query).get("p") or [""])[0]
        if key not in ("proxy", "dns", "vpn"):
            return self._redirect()
        verb = "iniciar" if start else "detener"

        def op(o: Orchestrator, progreso):
            steps = o.plan_start_one(key) if start else o.plan_stop_one(key)
            return o.execute(steps, f"{verb}_{key}", progress=progreso)

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

    def _serve_dashboard(self) -> None:
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
            ACTIVO: ("#7bd88f", "activo"),
            PARCIAL: ("#e0b341", "sin conectar"),
            APAGADO: ("#9aa0a6", "apagado"),
        }

        def dot(estado: str) -> str:
            color, txt = ETIQUETAS.get(estado, ETIQUETAS[APAGADO])
            return f"<span style='color:{color}'>&#9679; {txt}</span>"

        cards = "".join(
            f"<div class='card'><div class='value' style='font-size:1.1rem'>{dot(health[s.key])}</div>"
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

        sections = "".join(self._project_section(s, projects, health[s.key]) for s in PROJECT_SPECS)

        timeline = collect_logs(cfg, projects, per_source=40)[:60]
        if timeline:
            rows = "".join(
                f"<tr><td>{html_lib.escape(r.timestamp)}</td>"
                f"<td>{html_lib.escape(r.project)}</td>"
                f"<td>{html_lib.escape(r.kind)}</td>"
                f"<td>{html_lib.escape(r.detail)}</td></tr>"
                for r in timeline
            )
        else:
            rows = "<tr><td colspan='4'>Sin eventos todavía (o los proyectos nunca corrieron).</td></tr>"

        not_found = [s.display_name for s in PROJECT_SPECS if not projects[s.key].found]
        warn = (
            f"<p class='warn'>No encontré: {', '.join(not_found)}. Revisá las rutas en config/config.yaml.</p>"
            if not_found else ""
        )

        page = f"""<!DOCTYPE html><html lang="es"><head>
<meta charset="utf-8"><meta http-equiv="refresh" content="5">
<title>SecureCenter</title>
<style>
  * {{ box-sizing:border-box; }}
  body {{ font-family:-apple-system,"Segoe UI",sans-serif; background:#0f1115; color:#e6e6e6; padding:2rem; max-width:1000px; margin:0 auto; }}
  h1 {{ font-size:1.5rem; margin-bottom:0.25rem; }}
  h2 {{ font-size:1.05rem; }}
  .subtitle {{ color:#9aa0a6; font-size:0.85rem; margin-top:0; }}
  .stats {{ display:flex; gap:1rem; margin:1.25rem 0; flex-wrap:wrap; }}
  .card {{ background:#1a1d24; border-radius:8px; padding:0.9rem 1.3rem; min-width:150px; }}
  .card .label {{ color:#9aa0a6; font-size:0.9rem; }}
  .globalbar {{ display:flex; gap:0.5rem; flex-wrap:wrap; margin:1rem 0 0.5rem; }}
  .project {{ background:#141720; border:1px solid #2a2e37; border-radius:10px; padding:1rem 1.25rem; margin:1rem 0; }}
  .project .head {{ display:flex; justify-content:space-between; align-items:center; }}
  table {{ width:100%; border-collapse:collapse; margin-top:0.5rem; }}
  th,td {{ text-align:left; padding:0.45rem 0.7rem; border-bottom:1px solid #2a2e37; font-size:0.82rem; }}
  th {{ color:#9aa0a6; font-weight:500; }}
  a {{ color:#7fb2ff; }}
  .warn {{ color:#ff8a8a; font-size:0.85rem; }}
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
  button {{ background:#2a2e37; border:none; color:#e6e6e6; border-radius:6px; padding:0.5rem 1rem; cursor:pointer; font-size:0.85rem; }}
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
  <p class="subtitle">Centro de control del stack - se actualiza solo cada 5 segundos</p>
  {warn}{last_line}
  <div class="stats">{cards}</div>

  <div class="globalbar">
    <form method="get" action="/start-core" onsubmit="return confirm('¿Encender el núcleo (SecureProxy + SecureDNS) y dejarlo con inicio automático?')"><button class="ok-btn" type="submit">Encender núcleo</button></form>
    <form method="get" action="/start-vpn" onsubmit="return confirm('¿Encender la VPN? Levanta laboratorio, aprovisiona y conecta (1-3 min).')"><button type="submit">Encender VPN (todo en uno)</button></form>
    <form method="get" action="/stop-vpn" onsubmit="return confirm('¿Apagar solo la VPN?')"><button type="submit">Apagar VPN</button></form>
    <form method="get" action="/stop-all" onsubmit="return confirm('¿Apagar TODO (núcleo + VPN + autostart)?')"><button class="danger-btn" type="submit">Apagar todo</button></form>
    <form method="get" action="/panic" onsubmit="return confirm('PÁNICO: revierte firewall/kill switch y apaga todo, pase lo que pase. ¿Seguro?')"><button class="danger-btn" type="submit">PÁNICO</button></form>
  </div>

  <div class="tabs">
    <button class="tab-btn active" data-tab="servicios" onclick="showTab('servicios',this)">Servicios</button>
    <button class="tab-btn" data-tab="timeline" onclick="showTab('timeline',this)">Línea de tiempo</button>
  </div>

  <div id="tab-servicios" class="tab-panel active">
    {sections}
  </div>

  <div id="tab-timeline" class="tab-panel">
    <h2>Eventos de los tres, por hora</h2>
    <table><tr><th>Fecha/hora (UTC)</th><th>Proyecto</th><th>Tipo</th><th>Detalle</th></tr>{rows}</table>
  </div>

<script>
var K='securecenter_tab';
function showTab(n,b){{document.querySelectorAll('.tab-panel').forEach(function(e){{e.classList.remove('active');}});document.querySelectorAll('.tab-btn').forEach(function(e){{e.classList.remove('active');}});document.getElementById('tab-'+n).classList.add('active');b.classList.add('active');try{{localStorage.setItem(K,n);}}catch(e){{}}}}
(function(){{var s=null;try{{s=localStorage.getItem(K);}}catch(e){{}}if(s){{var b=document.querySelector('.tab-btn[data-tab="'+s+'"]');if(b)showTab(s,b);}}}})();
/* La consola arranca mostrando el final, como una terminal de verdad. Sin
   esto, cada refresco automatico (cada 5s) la devolveria al principio y
   habria que bajar a mano para ver lo ultimo que paso. */
(function(){{var c=document.getElementById('consola');if(c)c.scrollTop=c.scrollHeight;}})();
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

    def _project_section(self, spec, projects, estado_key: str) -> str:
        project = projects[spec.key]
        port = {
            "proxy": self.orchestrator.cfg.ports.proxy_dashboard,
            "dns": self.orchestrator.cfg.ports.dns_dashboard,
            "vpn": self.orchestrator.cfg.ports.vpn_dashboard,
        }[spec.key]
        alive = estado_key != APAGADO
        estado, color = {
            ACTIVO: ("corriendo", "#7bd88f"),
            PARCIAL: ("proceso arriba, sin conectar", "#e0b341"),
            APAGADO: ("apagado", "#9aa0a6"),
        }.get(estado_key, ("apagado", "#9aa0a6"))
        if not project.found:
            body = "<p class='warn'>No encontrado en el disco (revisá config/config.yaml).</p>"
        else:
            link = (
                f"<a href='http://127.0.0.1:{port}{spec.dashboard_path}' target='_blank'>abrir su dashboard &#8599;</a>"
                if alive else "<span style='color:#9aa0a6'>su dashboard abre cuando está corriendo</span>"
            )
            start_label = (
                f"Encender {spec.display_name} (todo en uno)"
                if spec.key == "vpn"
                else f"Encender {spec.display_name}"
            )
            stop_label = f"Apagar {spec.display_name}"
            # Ojo: el parámetro va en un input OCULTO, no en la URL del action.
            # Un formulario GET de HTML descarta la query string del action y la
            # reemplaza por sus propios campos; por eso '/stop-one?p=proxy' no
            # mandaba nunca el p y el botón "no hacía nada".
            body = (
                f"<div style='margin:0.5rem 0; display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap'>"
                f"<form method='get' action='/start-one'>"
                f"<input type='hidden' name='p' value='{spec.key}'>"
                f"<button class='ok-btn' type='submit'>{start_label}</button></form>"
                f"<form method='get' action='/stop-one' "
                f"onsubmit=\"return confirm('¿Seguro que querés apagar {spec.display_name}?')\">"
                f"<input type='hidden' name='p' value='{spec.key}'>"
                f"<button class='danger-btn' type='submit'>{stop_label}</button></form>"
                f"<span>{link}</span></div>"
            )
        return (
            f"<div class='project'><div class='head'>"
            f"<h2>{spec.display_name} <span style='font-size:0.8rem;color:#9aa0a6'>· {spec.role}</span></h2>"
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
