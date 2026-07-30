"""El orquestador: arma y ejecuta los planes de encendido/apagado.

SecureCenter NO reimplementa nada de los tres proyectos. Cada acción es una
secuencia de "pasos" (Step), y cada paso corre un script de su propio
proyecto (con el Python de SU venv) o un comando del sistema (setear el
proxy/DNS de Windows, registrar el inicio automático). Esto tiene dos
ventajas: es honesto (los proyectos siguen siendo la fuente de verdad) y es
testeable (en dry_run se puede inspeccionar el plan sin ejecutar nada).

Convenciones de los tres proyectos que este módulo aprovecha:
- Proxy: setea el proxy del sistema por registro (HKCU Internet Settings).
- DNS: setea el resolver del sistema (Set-DnsClientServerAddress 127.0.0.1).
- Ambos: script run_*.py (arranca, deja PID) y stop_*.py (mata por PID).
- VPN: lab_up -> provision -> connect para prender; disconnect + lab_down
  para apagar; restore_internet para el botón de pánico.
"""

import platform
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field

from .config_loader import Config
from .health import project_alive
from .logger_db import LoggerDB
from .procutil import (
    free_port,
    is_admin,
    popen_quiet,
    port_in_use,
    run_quiet,
    run_streaming,
    wait_port_listening,
)
from .projects import ManagedProject

CORE_AUTOSTART_TASK = "SecureCenterCoreAutostart"
PROXY_REG_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

# Tareas de inicio automático que crean los .bat individuales de cada
# proyecto. SecureCenter las borra al tomar el control: si no, resucitan los
# servicios en cada login y pelean con la orquestación (dos instancias por
# el mismo puerto, PIDs que quedan apuntando a la que murió).
PER_PROJECT_AUTOSTART_TASKS = {
    "proxy": "SecureProxyAutostart",
    "dns": "SecureDNSAutostart",
    "vpn": "SecureVPNDashboardAutostart",
}


@dataclass
class Step:
    label: str
    argv: list[str]
    cwd: str | None = None
    background: bool = False  # procesos que quedan corriendo (run_*.py)
    optional: bool = False  # si falla, seguir igual (apagar algo que no estaba)
    # Paso hecho en Python en vez de con un comando externo: devuelve
    # (ok, detalle). Se usa para matar/verificar puertos - más rápido que
    # PowerShell, sin ventanas, y con un resultado honesto que sí se chequea.
    func: Callable[[], tuple[bool, str]] | None = None
    # Cuánto esperar a que el paso termine. El default alcanza para todo
    # salvo el encendido completo de la VPN, que la primera vez construye la
    # imagen del laboratorio y puede tardar bastante más.
    timeout: int = 600


@dataclass
class OperationResult:
    ok: bool = True
    lines: list[str] = field(default_factory=list)


def diagnosticar(lineas: list[str]) -> list[str]:
    """Traduce errores crípticos de las herramientas a una causa entendible.

    El caso estrella: con el núcleo prendido, SecureProxy queda como proxy
    del SISTEMA, y Docker Desktop lo hereda. Pero Docker corre dentro de una
    máquina virtual (WSL2), donde 127.0.0.1 es la VM, NO tu PC: el proxy es
    inalcanzable desde ahí y las descargas de imágenes fallan con errores de
    'failed to resolve source metadata'. Sin esta pista, el error parece de
    la VPN cuando en realidad es un conflicto entre capas del stack."""
    texto = " ".join(lineas).lower()
    pistas: list[str] = []

    docker_falla = any(
        marca in texto
        for marca in ("docker.io", "registry-1.docker.io", "resolve source metadata",
                      "failed to do request", "docker compose falló")
    )
    if docker_falla:
        pistas.append(
            "PISTA: Docker no pudo descargar la imagen. Con el núcleo encendido, "
            "SecureProxy queda como proxy del sistema y Docker Desktop lo hereda, "
            "pero desde su máquina virtual 127.0.0.1 no es tu PC, así que no lo "
            "alcanza. Solución: en Docker Desktop -> Settings -> Resources -> "
            "Proxies, elegí 'Manual proxy configuration' y dejá los campos vacíos "
            "(o desmarcá el uso del proxy del sistema). Alternativa rápida: apagá "
            "el núcleo, encendé la VPN (que descarga la imagen una sola vez), y "
            "volvé a encender el núcleo."
        )
    if "wireguard" in texto and "no encontr" in texto:
        pistas.append(
            "PISTA: falta la app oficial de WireGuard (wireguard.com/install)."
        )
    return pistas


def _ps(command: str) -> list[str]:
    return ["powershell", "-NoProfile", "-Command", command]


def _is_windows() -> bool:
    return platform.system() == "Windows"


class Orchestrator:
    def __init__(
        self,
        cfg: Config,
        projects: dict[str, ManagedProject],
        logger_db: LoggerDB,
        dry_run: bool = False,
    ):
        self.cfg = cfg
        self.projects = projects
        self.logger_db = logger_db
        self.dry_run = dry_run

    # ---------------- construcción de pasos (testeable) ----------------

    def _run_script_step(
        self, key: str, script_rel: str, label: str, *, background: bool,
        optional: bool = False, timeout: int = 600,
    ) -> Step | None:
        project = self.projects.get(key)
        if project is None or not project.found:
            return None
        python = project.venv_python(windowless=background)
        script = project.script(script_rel)
        if python is None or script is None:
            return None
        # `-u` = salida sin buffer. Sin esto Python acumula lo que imprime
        # cuando la salida va a una tubería en vez de a una consola, y el
        # dashboard recibiría todo el texto de golpe al final: justo lo
        # contrario de una consola en vivo.
        return Step(
            label=label,
            argv=[str(python), "-u", str(script)],
            cwd=str(project.folder),
            background=background,
            optional=optional,
            timeout=timeout,
        )

    def _set_system_proxy_steps(self, enable: bool) -> list[Step]:
        if not _is_windows():
            return []
        if enable:
            addr = f"127.0.0.1:{self.cfg.ports.proxy_service}"
            return [
                Step("proxy del sistema: dirección", [
                    "reg", "add", PROXY_REG_KEY, "/v", "ProxyServer",
                    "/t", "REG_SZ", "/d", addr, "/f",
                ]),
                # SIN esto, el navegador manda TODO (incluidos los dashboards
                # locales 127.0.0.1:8890/8891/8899) a través del proxy, que no
                # sabe reenviarlos y devuelve 502/conexión rechazada. El bypass
                # <local> + 127.* hace que localhost salga directo, sin pasar
                # por el proxy. Es LA línea que faltaba.
                Step("proxy del sistema: excluir localhost (bypass)", [
                    "reg", "add", PROXY_REG_KEY, "/v", "ProxyOverride",
                    "/t", "REG_SZ", "/d", "localhost;127.0.0.1;<local>", "/f",
                ]),
                Step("proxy del sistema: activar", [
                    "reg", "add", PROXY_REG_KEY, "/v", "ProxyEnable",
                    "/t", "REG_DWORD", "/d", "1", "/f",
                ]),
                self._notify_wininet_step(),
            ]
        return [
            Step("proxy del sistema: desactivar", [
                "reg", "add", PROXY_REG_KEY, "/v", "ProxyEnable",
                "/t", "REG_DWORD", "/d", "0", "/f",
            ], optional=True),
            self._notify_wininet_step(),
        ]

    def _notify_wininet_step(self) -> Step | None:
        """Avisa a Windows que cambió la config de proxy, para que los
        navegadores YA abiertos la tomen al instante (si no, siguen usando la
        config vieja hasta reiniciarse - por eso un dashboard local 'cargaba
        infinito': el navegador todavía lo mandaba por el proxy)."""
        if not _is_windows():
            return None
        ps = (
            "$sig='[DllImport(\"wininet.dll\",SetLastError=true)]"
            "public static extern bool InternetSetOption(IntPtr h,int o,IntPtr b,int l);';"
            "$t=Add-Type -MemberDefinition $sig -Name W -Namespace I -PassThru;"
            "[void]$t::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0);"
            "[void]$t::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0)"
        )
        return Step("avisar al navegador del cambio de proxy", _ps(ps), optional=True)

    def _set_system_dns_steps(self, enable: bool) -> list[Step]:
        if not _is_windows():
            return []
        if enable:
            cmd = (
                "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object "
                "{ Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex "
                "-ServerAddresses '127.0.0.1' }"
            )
            return [Step("DNS del sistema: 127.0.0.1", _ps(cmd))]
        cmd = (
            "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object "
            "{ Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses }"
        )
        return [Step("DNS del sistema: automático (DHCP)", _ps(cmd), optional=True)]

    def _kill_ports_step(self, ports: list[int], label: str) -> Step | None:
        """Libera esos puertos matando a quien los escuche, y VERIFICA que
        hayan quedado libres.

        Antes esto era un comando de PowerShell con -ErrorAction
        SilentlyContinue: abría una ventana, tardaba ~1s en arrancar, y si el
        kill fallaba (típicamente por permisos) igual informaba OK mientras el
        servicio seguía prendido. Ahora se hace en Python: sin ventana, en
        milisegundos, y el resultado dice lo que realmente pasó."""
        if not _is_windows():
            return None

        def accion() -> tuple[bool, str]:
            detalles = []
            ok_total = True
            for port in ports:
                ok, detalle = free_port(port)
                detalles.append(detalle)
                ok_total = ok_total and ok
            return ok_total, "; ".join(detalles)

        # No es opcional: si un puerto no se libera, el usuario tiene que
        # enterarse (es exactamente el caso "aprieto apagar y sigue prendido").
        return Step(label, [], optional=False, func=accion)

    def _verify_down_step(self, ports: dict[str, int]) -> Step:
        """Chequeo final: confirma que los servicios quedaron abajo y, si
        alguno sigue arriba, lo dice con nombre y apellido."""

        def accion() -> tuple[bool, str]:
            siguen = [nombre for nombre, port in ports.items() if port_in_use(port)]
            if not siguen:
                return True, f"verificado: {', '.join(ports)} abajo"
            aviso = f"SIGUE(N) ARRIBA: {', '.join(siguen)}"
            if not is_admin():
                aviso += (
                    ". SecureCenter no está corriendo como administrador y esos "
                    "procesos arrancaron elevados. Se te tendría que haber "
                    "abierto un cartel de Windows pidiendo permisos: si lo "
                    "cancelaste o no apareció, abrí SecureCenter.bat (se "
                    "auto-eleva) y apagá desde ahí."
                )
            return False, aviso

        return Step("verificar que quedó apagado", [], optional=False, func=accion)

    def _verify_up_step(self, ports: dict[str, int]) -> Step:
        """Chequeo final de encendido: espera a que cada servicio escuche."""

        def accion() -> tuple[bool, str]:
            faltan = [nombre for nombre, port in ports.items() if not wait_port_listening(port, timeout=8)]
            if not faltan:
                return True, f"verificado: {', '.join(ports)} escuchando"
            return False, (
                f"NO arrancó: {', '.join(faltan)}. Probá correr su run_*.py a mano "
                "en una consola para ver el error."
            )

        return Step("verificar que quedó encendido", [], optional=False, func=accion)

    def _remove_task_step(self, task_name: str, label: str) -> Step | None:
        if not _is_windows():
            return None
        return Step(label, ["schtasks", "/delete", "/tn", task_name, "/f"], optional=True)

    def _adopt_ownership_steps(self) -> list[Step]:
        """Quita las tareas de autostart propias de cada proyecto, para que
        SecureCenter sea el único que gobierna el inicio con Windows."""
        steps: list[Step] = []
        for key in ("proxy", "dns"):
            step = self._remove_task_step(
                PER_PROJECT_AUTOSTART_TASKS[key],
                f"quitar autostart propio de {key} (lo maneja SecureCenter)",
            )
            if step:
                steps.append(step)
        return steps

    def _autostart_steps(self, enable: bool) -> list[Step]:
        if not _is_windows():
            return []
        if enable:
            from .config_loader import PROJECT_ROOT

            pythonw = PROJECT_ROOT / "venv" / "Scripts" / "pythonw.exe"
            script = PROJECT_ROOT / "scripts" / "autostart_core.py"
            return [
                Step("inicio automático con Windows (núcleo)", [
                    "schtasks", "/create", "/tn", CORE_AUTOSTART_TASK,
                    "/tr", f'"{pythonw}" "{script}"', "/sc", "onlogon", "/rl", "limited", "/f",
                ]),
            ]
        return [
            Step("quitar inicio automático", [
                "schtasks", "/delete", "/tn", CORE_AUTOSTART_TASK, "/f",
            ], optional=True),
        ]

    # -- planes completos --

    def plan_start_core(self) -> list[Step]:
        steps: list[Step] = []
        # Tomar el control: sacar los autostart propios de proxy/dns.
        steps += self._adopt_ownership_steps()
        # Un solo kill para los dos puertos (una llamada a PowerShell, no dos).
        kill = self._kill_ports_step(
            [self.cfg.ports.proxy_service, self.cfg.ports.dns_dashboard],
            "liberar puertos del núcleo (instancias previas)",
        )
        if kill:
            steps.append(kill)
        proxy = self._run_script_step("proxy", "scripts/run_proxy.py", "iniciar SecureProxy", background=True)
        if proxy:
            steps.append(proxy)
            steps += self._set_system_proxy_steps(True)
        dns = self._run_script_step("dns", "scripts/run_dns.py", "iniciar SecureDNS", background=True)
        if dns:
            steps.append(dns)
            steps += self._set_system_dns_steps(True)
        steps += self._autostart_steps(True)
        if _is_windows():
            steps.append(self._verify_up_step({
                "SecureProxy": self.cfg.ports.proxy_service,
                "SecureDNS": self.cfg.ports.dns_dashboard,
            }))
        return steps

    def plan_stop_core(self) -> list[Step]:
        steps: list[Step] = []
        # Stops 'prolijos' (limpian PID) - rápidos, sin PowerShell.
        for key, script, name in (
            ("dns", "scripts/stop_dns.py", "SecureDNS"),
            ("proxy", "scripts/stop_proxy.py", "SecureProxy"),
        ):
            stop = self._run_script_step(key, script, f"detener {name} (prolijo)", background=False, optional=True)
            if stop:
                steps.append(stop)
        # Un solo kill robusto para los dos puertos.
        kill = self._kill_ports_step(
            [self.cfg.ports.dns_dashboard, self.cfg.ports.proxy_service],
            "asegurar puertos del núcleo cerrados",
        )
        if kill:
            steps.append(kill)
        steps += self._set_system_dns_steps(False)
        steps += self._set_system_proxy_steps(False)
        # Sacar autostart viejos de cada proyecto + el del núcleo.
        for key, name in (("dns", "SecureDNS"), ("proxy", "SecureProxy")):
            task = self._remove_task_step(PER_PROJECT_AUTOSTART_TASKS[key], f"quitar autostart viejo de {name}")
            if task:
                steps.append(task)
        steps += self._autostart_steps(False)
        if _is_windows():
            steps.append(self._verify_down_step({
                "SecureProxy": self.cfg.ports.proxy_service,
                "SecureDNS": self.cfg.ports.dns_dashboard,
            }))
        return steps

    def plan_start_vpn(self) -> list[Step]:
        """El botón 'todo en uno': prende el dashboard de la VPN (para que su
        estado sea visible y el chequeo de salud lo vea) y después dispara UN
        solo script que hace todo el encendido.

        El dashboard va PRIMERO y en segundo plano: así queda disponible
        aunque el handshake tarde, y no depende de que 'conectar' termine
        bien (si el servidor todavía no está, el túnel no hace handshake,
        pero igual querés ver el dashboard).

        Por qué un solo paso y no tres (laboratorio, aprovisionar, conectar):
        encadenados desde acá, cada script arrancaba apenas terminaba el
        anterior, sin ninguna espera en el medio. Eso producía fallas de
        carrera -apt corriendo antes de que el contenedor tuviera red, ssh
        antes de que sshd aceptara sesiones- que aparecían solo al encender
        desde el dashboard y no desde el .bat de la VPN, donde uno tarda en
        apretar la siguiente opción. `scripts/start_vpn.py` hace las tres
        etapas con las esperas adentro, además de abrir Docker Desktop si
        está cerrado."""
        steps: list[Step] = []
        dash = self._run_script_step("vpn", "scripts/run_dashboard.py", "VPN: iniciar su dashboard", background=True)
        if dash:
            steps.append(dash)
        encender = self._run_script_step(
            "vpn", "scripts/start_vpn.py",
            "VPN: encendido completo (Docker, laboratorio, aprovisionar, conectar)",
            background=False,
            # 20 minutos: la PRIMERA vez hay que esperar a que Docker Desktop
            # arranque su máquina virtual y a que se construya la imagen del
            # laboratorio. Las veces siguientes tarda segundos.
            timeout=1200,
        )
        if encender:
            steps.append(encender)
        return steps

    def plan_stop_vpn(self) -> list[Step]:
        steps: list[Step] = []
        for script, label in (
            ("scripts/disconnect_vpn.py", "VPN: desconectar (kill switch + túnel)"),
            ("scripts/lab_down.py", "VPN: bajar laboratorio"),
            ("scripts/stop_dashboard.py", "VPN: detener dashboard (prolijo)"),
        ):
            step = self._run_script_step("vpn", script, label, background=False, optional=True)
            if step:
                steps.append(step)
        # Robusto: matar lo que quede en el puerto del dashboard de la VPN y
        # sacar su autostart propio, para que no reviva en el próximo login.
        kill = self._kill_ports_step([self.cfg.ports.vpn_dashboard], f"asegurar puerto {self.cfg.ports.vpn_dashboard} cerrado (VPN)")
        if kill:
            steps.append(kill)
        task = self._remove_task_step(PER_PROJECT_AUTOSTART_TASKS["vpn"], "quitar autostart viejo de la VPN")
        if task:
            steps.append(task)
        return steps

    def plan_stop_all(self, vpn_was_running: bool | None = None) -> list[Step]:
        """Apaga TODO. La parte de la VPN se incluye solo si la VPN está (o
        estaba) corriendo - si nunca se prendió, se omite, tal como se pidió,
        pero igual se cierra el núcleo y se saca su inicio automático."""
        if vpn_was_running is None:
            vpn_was_running = project_alive("vpn", self.cfg)
        steps: list[Step] = []
        if vpn_was_running:
            steps += self.plan_stop_vpn()
        steps += self.plan_stop_core()
        return steps

    def plan_panic(self) -> list[Step]:
        """Botón de pánico: revierte TODO incondicionalmente, sin depender de
        detección. Primero restaura internet (revierte el kill switch de la
        VPN pase lo que pase), después apaga núcleo y quita autostart."""
        steps: list[Step] = []
        restore = self._run_script_step(
            "vpn", "scripts/restore_internet.py", "VPN: RESTAURAR INTERNET (revertir firewall)",
            background=False, optional=True,
        )
        if restore:
            steps.append(restore)
        steps += self.plan_stop_vpn()
        steps += self.plan_stop_core()
        return steps

    def _start_one_core(self, key: str, run_script: str, name: str, port: int, system_steps: list[Step]) -> list[Step]:
        run = self._run_script_step(key, run_script, f"iniciar {name}", background=True)
        if run is None:
            return []
        steps: list[Step] = []
        kill = self._kill_ports_step([port], f"liberar puerto {port} ({name})")
        if kill:
            steps.append(kill)
        steps.append(run)
        steps += system_steps
        if _is_windows():
            steps.append(self._verify_up_step({name: port}))
        return steps

    def _stop_one_core(self, key: str, stop_script: str, name: str, port: int, system_steps: list[Step]) -> list[Step]:
        steps: list[Step] = []
        # Primero se saca el autostart: si la tarea programada lo relanzara
        # justo después de matarlo, el servicio "revive" y parece que apagar
        # no hizo nada.
        task = self._remove_task_step(PER_PROJECT_AUTOSTART_TASKS[key], f"quitar autostart viejo de {name}")
        if task:
            steps.append(task)
        stop = self._run_script_step(key, stop_script, f"detener {name} (prolijo)", background=False, optional=True)
        if stop:
            steps.append(stop)
        kill = self._kill_ports_step([port], f"asegurar puerto {port} cerrado ({name})")
        if kill:
            steps.append(kill)
        steps += system_steps
        if _is_windows():
            steps.append(self._verify_down_step({name: port}))
        return steps

    def plan_start_one(self, key: str) -> list[Step]:
        if key == "proxy":
            return self._start_one_core("proxy", "scripts/run_proxy.py", "SecureProxy", self.cfg.ports.proxy_service, self._set_system_proxy_steps(True))
        if key == "dns":
            return self._start_one_core("dns", "scripts/run_dns.py", "SecureDNS", self.cfg.ports.dns_dashboard, self._set_system_dns_steps(True))
        if key == "vpn":
            return self.plan_start_vpn()
        return []

    def plan_stop_one(self, key: str) -> list[Step]:
        if key == "proxy":
            return self._stop_one_core("proxy", "scripts/stop_proxy.py", "SecureProxy", self.cfg.ports.proxy_service, self._set_system_proxy_steps(False))
        if key == "dns":
            return self._stop_one_core("dns", "scripts/stop_dns.py", "SecureDNS", self.cfg.ports.dns_dashboard, self._set_system_dns_steps(False))
        if key == "vpn":
            return self.plan_stop_vpn()
        return []

    # ---------------- ejecución ----------------

    def execute(self, steps: list[Step], operation: str, progress=None) -> OperationResult:
        """Ejecuta el plan. Todos los subprocesos van sin ventana (adiós al
        PowerShell/cmd que parpadeaba) y los pasos que fallan sin ser
        opcionales cortan la operación informando el motivo real.

        `progress` es una función opcional que recibe cada línea APENAS
        ocurre, incluida la salida de los scripts mientras corren. Es lo que
        alimenta la consola en vivo del dashboard: sin esto, una operación de
        varios minutos no muestra nada hasta terminar.
        """
        result = OperationResult()

        def emitir(linea: str) -> None:
            result.lines.append(linea)
            if progress is not None:
                progress(linea)

        self.logger_db.log_event(f"{operation}_start", f"{len(steps)} pasos")
        for step in steps:
            if self.dry_run:
                detalle = " ".join(step.argv) if step.argv else "(paso interno de Python)"
                emitir(f"[dry-run] {step.label}: {detalle}")
                continue

            # Paso hecho en Python (liberar puertos, verificar): sin procesos
            # externos y con un resultado que sí se chequea.
            if step.func is not None:
                try:
                    ok, detalle = step.func()
                except Exception as exc:  # noqa: BLE001
                    ok, detalle = False, f"error inesperado: {exc}"
                if ok:
                    emitir(f"OK: {step.label} ({detalle})")
                elif step.optional:
                    emitir(f"omitido: {step.label} ({detalle})")
                else:
                    result.ok = False
                    emitir(f"ERROR: {step.label} -> {detalle}")
                continue

            try:
                if step.background:
                    popen_quiet(step.argv, cwd=step.cwd)
                    emitir(f"OK (en segundo plano): {step.label}")
                else:
                    # Se avisa ANTES de arrancar: en un paso que tarda
                    # minutos, ver "arrancó" enseguida es la diferencia entre
                    # parecer colgado y parecer que está trabajando.
                    emitir(f"> {step.label}...")
                    ultimas: list[str] = []

                    def eco(linea: str, _ultimas=ultimas) -> None:
                        _ultimas.append(linea)
                        if progress is not None:
                            progress(f"   {linea}")

                    codigo = run_streaming(
                        step.argv, cwd=step.cwd, timeout=step.timeout, on_line=eco
                    )
                    # Las líneas del script ya se mostraron en vivo; en el
                    # resultado final se guardan también, para que el detalle
                    # quede completo cuando la operación termina.
                    result.lines.extend(f"   {linea}" for linea in ultimas)
                    if codigo == 0:
                        emitir(f"OK: {step.label}")
                    elif step.optional:
                        emitir(f"omitido (no estaba activo): {step.label}")
                    else:
                        result.ok = False
                        motivo = ultimas[-1] if ultimas else f"terminó con código {codigo}"
                        emitir(f"ERROR: {step.label} -> {motivo[:200]}")
                        break
            except (OSError, subprocess.SubprocessError) as exc:
                if step.optional:
                    emitir(f"omitido ({exc}): {step.label}")
                else:
                    result.ok = False
                    emitir(f"ERROR: {step.label} -> {exc}")
                    break

        # Aviso proactivo: la causa más común de "aprieto y no pasa nada" es
        # estar corriendo sin permisos de administrador.
        if not result.ok and _is_windows() and not self.dry_run and not is_admin():
            emitir(
                "PISTA: SecureCenter no está corriendo como administrador. "
                "Cerralo y abrilo con SecureCenter.bat (se auto-eleva)."
            )
        for pista in diagnosticar(result.lines):
            emitir(pista)

        self.logger_db.log_event(operation, "; ".join(result.lines[-3:]) or "sin pasos", ok=result.ok)
        return result
