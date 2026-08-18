"""El orquestador: arma y ejecuta los planes de encendido/apagado.

SecureCenter NO reimplementa nada de los proyectos administrados. Cada acción es una
secuencia de "pasos" (Step), y cada paso corre un script de su propio
proyecto (con el Python de SU venv) o un comando del sistema (setear el
proxy/DNS de Windows, registrar el inicio automático). Esto tiene dos
ventajas: es honesto (los proyectos siguen siendo la fuente de verdad) y es
testeable (en dry_run se puede inspeccionar el plan sin ejecutar nada).

Convenciones de los proyectos que este módulo aprovecha:
- Proxy: setea el proxy del sistema por registro (HKCU Internet Settings).
- DNS: setea el resolver del sistema (Set-DnsClientServerAddress 127.0.0.1).
- Ambos: script run_*.py (arranca, deja PID) y stop_*.py (mata por PID).
- VPN: lab_up -> provision -> connect para prender; disconnect + lab_down
  para apagar; restore_internet para el botón de pánico.
"""

import os
import platform
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field

from .config_loader import Config
from .health import project_alive
from . import procutil
from .logger_db import LoggerDB
from .procutil import (
    free_port,
    is_admin,
    esperar_puertos,
    popen_quiet,
    port_in_use,
    run_streaming,
    wait_port_listening,
)
from .projects import PROJECT_SPECS, ManagedProject

CORE_AUTOSTART_TASK = "SecureCenterCoreAutostart"
PROXY_REG_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

# Tareas de inicio automático que crean los .bat individuales de cada
# proyecto. SecureCenter las borra al tomar el control: si no, resucitan los
# servicios en cada login y pelean con la orquestación (dos instancias por
# el mismo puerto, PIDs que quedan apuntando a la que murió).
# La tarea de inicio automático que cada proyecto se ponía por su cuenta, y que
# SecureCenter le saca para ser el único dueño del arranque.
#
# NO están todos, y está bien: Secure-Scanner y Secure-Agent nunca se pusieron
# una. Por eso SIEMPRE se busca acá con `.get()` y nunca con corchetes: la
# versión con corchetes tiraba KeyError al apagar el scanner, y como eso pasaba
# adentro del hilo de fondo, el botón no hacía absolutamente nada y no aparecía
# ningún error en ningún lado. Es el mismo error que ya había pasado con el
# puerto de la tarjeta del panel.
PER_PROJECT_AUTOSTART_TASKS = {
    "proxy": "SecureProxyAutostart",
    "dns": "SecureDNSAutostart",
    "vpn": "SecureVPNDashboardAutostart",
    "hips": "SecureHIPSAutostart",
    "intel": "SecureIntelAutostart",
}

# Lo que un proyecto necesita en su `.env` para poder arrancar.
#
# Secure-Agent no arranca sin token, y hace bien: un token por defecto es un
# token público. Pero se lanza en segundo plano, así que el proceso imprimía el
# motivo, devolvía 1 y se moría, y desde SecureCenter eso se ve EXACTAMENTE
# igual que "nunca arrancó". El panel quedaba en "apagado" para siempre sin
# decir por qué.
#
# Se chequea antes de lanzar, y si falta se explica.
SECRETOS_REQUERIDOS = {
    "agente": (
        "SECUREAGENT_TOKEN",
        'python -c "import secrets; print(secrets.token_urlsafe(32))"',
    ),
}

# Qué forma el "núcleo": lo que se prende con un botón y queda arrancando con
# Windows. Son los que no molestan en el uso diario. La VPN queda afuera a
# propósito y tiene su botón aparte, para que nunca te corte una partida sin
# querer.
# Los SEIS. La VPN es la única que queda afuera, y es la única que se justifica
# que quede afuera: mete todo tu tráfico por un túnel y en modo laboratorio
# rompe cosas sensibles al NAT, como los juegos online. Todo lo demás se puede
# tener prendido todo el día sin que se note.
#
# Secure-Scanner y Secure-Agent estuvieron un tiempo afuera, con una puerta que
# los dejaba entrar solo si estaban configurados. Se sacó: "encender núcleo"
# tiene que prender el núcleo, y que la lista de lo que prende dependa de tres
# condiciones invisibles es peor que el problema que resolvía. Si a alguno le
# falta algo para arrancar, se dice en un paso y los otros cinco siguen.
CLAVES_DEL_NUCLEO = ("proxy", "dns", "hips", "intel", "scanner", "agente")

# Qué script levanta y baja a cada uno. UNA sola tabla, y ese es el punto.
#
# ESTA TABLA EXISTE POR UN BUG QUE COSTÓ CARO.
#
# La lista de "qué es el núcleo" estaba escrita a mano en tres lugares: el plan
# de encendido, el de apagado, y `autostart_core.py`, que es el que relanza
# todo cuando prendés la máquina. Los dos primeros se fueron actualizando; el
# tercero quedó con "proxy y dns" desde el día uno.
#
# El resultado es el peor posible: encendías el núcleo y arrancaban los seis,
# el panel te lo confirmaba, apagabas la máquina, la prendías al otro día, y
# volvían DOS. Sin un error, sin un aviso, y con un panel que decía la verdad
# sobre un estado que ya no era el que vos habías dejado. Cuatro de los seis
# servicios te estaban protegiendo hasta que reiniciaste.
#
# El orden importa poco pero no es al azar: Secure-Intel y los dos últimos van
# al final porque no están en el camino de ninguna conexión.
SERVICIOS_DEL_NUCLEO = (
    ("proxy", "SecureProxy", "scripts/run_proxy.py", "scripts/stop_proxy.py"),
    ("dns", "SecureDNS", "scripts/run_dns.py", "scripts/stop_dns.py"),
    ("hips", "SecureHIPS", "scripts/run_hips.py", "scripts/stop_hips.py"),
    ("intel", "Secure-Intel", "scripts/run_intel.py", "scripts/stop_intel.py"),
    ("scanner", "Secure-Scanner", "scripts/run_scanner.py", "scripts/stop_scanner.py"),
    ("agente", "Secure-Agent (servidor)", "scripts/run_servidor.py",
     "scripts/stop_servidor.py"),
)


@dataclass
class Step:
    label: str
    argv: list[str]
    cwd: str | None = None
    background: bool = False  # procesos que quedan corriendo (run_*.py)
    # Dónde se guarda lo que imprime un paso de segundo plano. Sin esto, un
    # servicio que arranca, dice por qué no puede seguir y se muere deja el
    # mismo rastro que uno que arrancó bien.
    log: str | None = None
    # Los pasos CONSECUTIVOS marcados con la misma etiqueta de tanda se corren
    # a la vez. Es para los grupos donde el orden no importa y el costo es
    # arrancar un intérprete de Python por cada uno: apagar los seis servicios
    # del núcleo eran seis arranques en fila, y son independientes.
    #
    # Vacío = se corre solo, en orden, como siempre. Lo que se paralelice tiene
    # que ser una decisión escrita en cada plan, no el default.
    tanda: str = ""
    optional: bool = False  # si falla, seguir igual (apagar algo que no estaba)
    # Paso hecho en Python en vez de con un comando externo: devuelve
    # (ok, detalle). Se usa para matar/verificar puertos - más rápido que
    # PowerShell, sin ventanas, y con un resultado honesto que sí se chequea.
    func: Callable[[], tuple[bool, str]] | None = None
    # Cuánto esperar a que el paso termine. El default alcanza para todo
    # salvo el encendido completo de la VPN, que la primera vez construye la
    # imagen del laboratorio y puede tardar bastante más.
    timeout: int = 600
    # Sobre QUÉ actúa el paso, cuando eso no se puede leer del argv.
    #
    # Apareció con la capa de arranque: antes, "quitar el autostart de la VPN"
    # era un `schtasks /delete /tn SecureVPNDashboardAutostart`, así que el
    # nombre de la tarea estaba a la vista en el comando y se podía verificar.
    # Ahora el paso es una función que por dentro llama al backend que
    # corresponda, y el nombre quedaba escondido en un closure: imposible de
    # revisar desde afuera, y encima invisible en el log. Acá vuelve a estar.
    objetivo: str = ""


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
        optional: bool = False, timeout: int = 600, tanda: str = "",
    ) -> Step | None:
        project = self.projects.get(key)
        if project is None or not project.found:
            return None
        script = project.script(script_rel)
        python = project.venv_python(windowless=background)
        if script is None:
            return None
        if python is None or not script.exists():
            # No se devuelve None (eso lo saltearía en silencio) ni se arma el
            # comando igual (eso da «[WinError 2] no puede encontrar el
            # archivo», que no dice cuál ni qué hacer). Se devuelve un paso
            # que falla explicando exactamente qué falta y cómo arreglarlo.
            return self._paso_falta_algo(project, script, script_rel, label,
                                         python is None)
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
            log=str(self.ruta_de_arranque(key)) if background else None,
            tanda=tanda,
        )

    def _comando_de_preparar(self) -> str:
        """El comando de `preparar.py`, con la ruta ENTERA.

        Decía `python scripts/preparar.py --hacelo` a secas, y eso solo
        funciona parado en la carpeta de SecureCenter. Quien lee el mensaje
        está mirando el panel o una consola abierta en OTRO proyecto (es el que
        acaba de fallar), así que lo copia, lo pega, y le dice "can't open
        file". Un comando que hay que saber desde dónde correr no es una
        instrucción, es una adivinanza.
        """
        from .config_loader import PROJECT_ROOT

        return f'python "{PROJECT_ROOT / "scripts" / "preparar.py"}" --hacelo'

    def ruta_de_arranque(self, key: str):
        """Dónde queda lo que imprimió el último arranque de ese proyecto.

        En el `data/` de SecureCenter y no en el del proyecto: es un dato de
        la orquestación, no del proyecto, y así queda todo junto para mirar.
        """
        from .config_loader import PROJECT_ROOT

        return PROJECT_ROOT / "data" / f"arranque-{key}.log"

    def _paso_falta_algo(self, project, script, script_rel: str, label: str,
                         sin_venv: bool) -> Step:
        """Un paso que falla con instrucciones, en vez de con un WinError."""
        nombre = project.spec.display_name
        carpeta = project.folder
        atajo = self._comando_de_preparar()

        def accion() -> tuple[bool, str]:
            if sin_venv:
                # Se ofrece el atajo primero y el comando largo después. El
                # comando largo es correcto y es lo que estaba, pero son dos
                # líneas con comillas que hay que copiar bien por cada
                # proyecto: decir qué hacer es mejor que fallar callado, y
                # hacerlo es mejor que decirlo.
                if _is_windows():
                    receta = (f'cd "{carpeta}" && python -m venv venv && '
                              r'venv\Scripts\pip install -r requirements.txt')
                else:
                    receta = (f'cd "{carpeta}" && python3 -m venv venv && '
                              'venv/bin/pip install -r requirements.txt')
                return False, (
                    f"{nombre} no tiene su entorno virtual creado todavía. "
                    f"Lo más rápido, desde donde estés:  {atajo}  "
                    f"(prepara todos los que falten). A mano:  {receta}")
            return False, (
                f"a {nombre} le falta {script_rel}. ¿Es una versión vieja de "
                f"ese proyecto? Fijate en {carpeta}")

        # Opcional: que a un proyecto le falte el venv no puede impedir que
        # arranque el resto del núcleo. Se ve el error, con su explicación, y
        # los otros siguen.
        return Step(label, [], optional=True, func=accion)

    def _paso_no_aplica(self, capacidad: dict) -> Step:
        """Un paso que no hace nada y lo dice.

        Reemplaza a los `return []` que había repartidos por acá. La
        diferencia es todo: una lista vacía hace que el plan salga en verde
        sin haber configurado nada, y quien lo mira cree que quedó puesto.
        """
        def avisar() -> tuple[bool, str]:
            return True, f"{capacidad['nombre']}: {capacidad['detalle']}"

        return Step(f"{capacidad['nombre']} (no aplica acá)", [],
                    optional=True, func=avisar)

    def _set_system_proxy_steps(self, enable: bool) -> list[Step]:
        if not _is_windows():
            # Solo al encender: al apagar no hay nada que aclarar, y repetir
            # el aviso en cada apagado es ruido.
            if not enable:
                return []
            from . import capacidades as mod_cap

            return [self._paso_no_aplica(mod_cap.proxy_del_sistema())]
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
        navegadores YA abiertos la tomen al instante."""
        if not _is_windows():
            return None

        def accion() -> tuple[bool, str]:
            import ctypes
            # 39 = INTERNET_OPTION_SETTINGS_CHANGED
            # 37 = INTERNET_OPTION_REFRESH
            try:
                ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)
                ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)
                return True, "notificado vía wininet"
            except Exception as exc:
                return False, f"falló ctypes wininet: {exc}"

        return Step("avisar al navegador del cambio de proxy", [], optional=True, func=accion)

    def _set_system_dns_steps(self, enable: bool) -> list[Step]:
        if not _is_windows():
            if not enable:
                return []
            from . import capacidades as mod_cap

            return [self._paso_no_aplica(mod_cap.dns_del_sistema(self.cfg))]
        # Se delega en el `net_config.py` de SecureDNS en vez de armar el
        # comando acá. Antes eran DOS copias del mismo PowerShell, y esa
        # duplicación fue el bug: SecureDNS aprendió a guardar el DNS anterior
        # y a dejar un respaldo detrás del nuestro, y SecureCenter siguió
        # pisando los adaptadores a pelo con 127.0.0.1 solo. Encender el
        # núcleo desde el panel dejaba la máquina expuesta al agujero del
        # reinicio; encenderlo desde el .bat de SecureDNS, no.
        #
        # Se llaman las variantes "_si_corresponde" y no las directas por el
        # mismo motivo. Desde que SecureDNS puede correr en modo Pi-hole (el
        # que resuelve es Pi-hole y SecureDNS solo analiza), poner 127.0.0.1
        # en el adaptador apuntaría la máquina a un puerto donde no escucha
        # nadie: internet cortado y ni un mensaje de error. Quién decide eso
        # es SecureDNS, que es el que conoce su propio modo; SecureCenter
        # pregunta y obedece. Volver a decidirlo acá sería reintroducir la
        # duplicación que causó el apagón.
        funcion = ("tomar_el_dns_si_corresponde" if enable
                   else "devolver_el_dns_si_corresponde")
        etiqueta = ("DNS del sistema: 127.0.0.1 (con respaldo detrás)"
                    if enable else "DNS del sistema: devolverlo como estaba")
        paso = self._run_python_step(
            "dns", f"from securedns import net_config; print(net_config.{funcion}())",
            etiqueta, optional=not enable)
        if paso is not None:
            return [paso]
        # SecureDNS no está instalado: se hace lo mínimo acá para no dejar la
        # máquina apuntando a un resolver que no existe.
        if enable:
            return []
        cmd = (
            "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object "
            "{ Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses }"
        )
        return [Step("DNS del sistema: automático (DHCP)", _ps(cmd), optional=True)]

    def _run_python_step(self, key: str, codigo: str, label: str, *,
                         optional: bool = False) -> Step | None:
        """Corre una línea de Python DENTRO del venv de otro proyecto.

        Es la forma de reusar su código sin importarlo acá: cada proyecto
        tiene sus propias dependencias y su propio intérprete.
        """
        project = self.projects.get(key)
        if project is None or not project.found:
            return None
        python = project.venv_python()
        if python is None:
            return None
        return Step(label, [str(python), "-c",
                            "import sys; sys.path.insert(0, 'src'); " + codigo],
                    cwd=str(project.folder), optional=optional, timeout=90)

    def _kill_ports_step(self, ports: list[int], label: str) -> Step | None:
        """Libera esos puertos matando a quien los escuche, y VERIFICA que
        hayan quedado libres.

        Antes esto era un comando de PowerShell con -ErrorAction
        SilentlyContinue: abría una ventana, tardaba ~1s en arrancar, y si el
        kill fallaba (típicamente por permisos) igual informaba OK mientras el
        servicio seguía prendido. Ahora se hace en Python: sin ventana, en
        milisegundos, y el resultado dice lo que realmente pasó.

        NO lleva guarda de Windows, a diferencia de los pasos que tocan el
        registro o las tareas programadas. Matar por puerto es de las pocas
        cosas del orquestador que ya son multiplataforma de punta a punta:
        `procutil` sabe leer `netstat -ano` en Windows y `ss -ltnp` en Linux,
        y matar con `taskkill` o con SIGKILL según el sistema. Cuando esto
        estaba detrás de `if not _is_windows(): return None`, en Linux apagar
        el núcleo no liberaba ningún puerto, y encima el test que exige que
        este paso NO sea opcional fallaba en el CI, que corre en Ubuntu."""

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

    def _verify_up_step(self, ports: dict[str, int],
                        claves: dict | None = None) -> Step:
        """Chequeo final de encendido: espera a que cada servicio escuche.

        Y cuando alguno no arrancó, DICE POR QUÉ. Antes decía "probá correr su
        run_*.py a mano en una consola para ver el error", que es pedirle a la
        persona que haga de depurador: el error ya se había impreso, lo que
        pasaba es que la salida iba a DEVNULL y se tiraba.

        Ahora los procesos de segundo plano escriben en `data/arranque-*.log` y
        acá se leen las últimas líneas del que falló. La diferencia práctica es
        entre "no arrancó, andá a averiguar" y "no arrancó: el rango de red no
        es válido".
        """
        claves = claves or {}

        def accion() -> tuple[bool, str]:
            # Todos a la vez. Antes era uno por uno con ocho segundos cada
            # uno: con seis servicios, un encendido donde nada arranca se
            # quedaba 48 segundos esperando en fila a procesos que ya se
            # habían lanzado todos juntos.
            faltan = esperar_puertos(ports, timeout=8)
            if not faltan:
                return True, f"verificado: {', '.join(ports)} escuchando"

            partes = []
            for nombre in faltan:
                clave = claves.get(nombre)
                salida = (procutil.ultimas_lineas(self.ruta_de_arranque(clave))
                          if clave else "")
                partes.append(f"{nombre}: {salida}" if salida
                              else f"{nombre} (no dejó ningún mensaje)")
            return False, (
                "NO arrancó -> " + " || ".join(partes)
                + ". Lo de arriba es lo que imprimió al morirse."
            )

        return Step("verificar que quedó encendido", [], optional=False, func=accion)

    def _arranque(self):
        """El backend de arranque automático de esta máquina.

        Se guarda en el objeto para no volver a mirar el sistema (y, en Linux,
        a preguntar por el linger) en cada paso de cada plan.
        """
        if getattr(self, "_backend_arranque", None) is None:
            from . import arranque

            self._backend_arranque = arranque.elegir(self.cfg)
        return self._backend_arranque

    def _remove_task_step(self, task_name: str, label: str) -> Step | None:
        """Quitar un arranque automático, en el sistema que sea.

        Antes esto devolvía None fuera de Windows, lo que en Linux significaba
        que apagar la suite no desactivaba nada: los servicios volvían a
        levantarse en el próximo arranque después de que vos los apagaste.
        """
        backend = self._arranque()
        if not backend.disponible:
            return None

        def accion() -> tuple[bool, str]:
            return backend.quitar(task_name)

        return Step(label, [], optional=True, func=accion, objetivo=task_name)

    def _paso_sacar_varios_autostart(self, keys, etiqueta: str) -> Step | None:
        """Saca varios arranques automáticos en UN paso, en paralelo.

        Eran cuatro pasos, cada uno con su `schtasks /delete`, o sea cuatro
        procesos externos en fila. Ninguno depende del otro y cada uno tarda
        entre 200 y 500 ms: en fila son casi dos segundos, y pasa dos veces
        (al encender y al apagar).

        El `objetivo` lleva todos los nombres, así que el paso sigue siendo
        auditable: se ve exactamente qué tareas toca.
        """
        from concurrent.futures import ThreadPoolExecutor

        backend = self._arranque()
        if not backend.disponible:
            return None
        tareas = [PER_PROJECT_AUTOSTART_TASKS[k] for k in keys
                  if PER_PROJECT_AUTOSTART_TASKS.get(k)]
        if not tareas:
            return None

        def accion() -> tuple[bool, str]:
            with ThreadPoolExecutor(max_workers=len(tareas)) as pool:
                resultados = list(pool.map(backend.quitar, tareas))
            detalles = [d for _ok, d in resultados if d]
            # Optional: que una tarea no exista es el resultado que se pedía.
            return True, "; ".join(detalles) or "no había ninguna"

        return Step(etiqueta, [], optional=True, func=accion,
                    objetivo=" ".join(tareas))

    def _paso_sacar_autostart(self, key: str, etiqueta: str) -> Step | None:
        """Saca el autostart propio de un proyecto, si tenía uno.

        Un proyecto sin tarea propia (Secure-Scanner, Secure-Agent) devuelve
        None y no pasa nada. Esta función existe para que buscar en el
        diccionario esté escrito UNA vez: cuando estaba con corchetes en tres
        lugares, agregar un proyecto que no tuviera tarea tiraba KeyError en
        uno de ellos.
        """
        tarea = PER_PROJECT_AUTOSTART_TASKS.get(key)
        if not tarea:
            return None
        return self._remove_task_step(tarea, etiqueta)

    def _adopt_ownership_steps(self) -> list[Step]:
        """Quita las tareas de autostart propias de cada proyecto, para que
        SecureCenter sea el único que gobierna el inicio con Windows."""
        step = self._paso_sacar_varios_autostart(
            CLAVES_DEL_NUCLEO,
            "quitar los autostart propios de cada proyecto (los maneja SecureCenter)")
        return [step] if step else []

    def _interprete_de_arranque(self):
        """Con qué se lanza `autostart_core.py` al arrancar la máquina.

        En Windows `pythonw.exe`, que corre sin abrir una ventana de consola.
        En Linux `python`, porque no existe esa distinción: systemd ya lo
        corre sin terminal.
        """
        from .config_loader import PROJECT_ROOT

        if _is_windows():
            return PROJECT_ROOT / "venv" / "Scripts" / "pythonw.exe"
        return PROJECT_ROOT / "venv" / "bin" / "python"

    def _autostart_steps(self, enable: bool) -> list[Step]:
        """Dejar (o sacar) el núcleo arrancando solo con la máquina.

        El cómo lo decide `arranque.py`: tarea programada en Windows, unidad
        de systemd en Linux. Acá solo se dice QUÉ se quiere.

        Antes esto era `if not _is_windows(): return []`, y esa línea era el
        agujero: en Linux, encender el núcleo salía todo en verde y no dejaba
        absolutamente nada configurado para el próximo arranque. Ni un error,
        ni un aviso.
        """
        from .config_loader import PROJECT_ROOT

        backend = self._arranque()
        if not backend.disponible:
            # No se devuelve lista vacía: se devuelve un paso que EXPLICA.
            # Que una capacidad no exista en este sistema hay que decirlo,
            # no esconderlo detrás de un plan que sale todo bien.
            motivo = "; ".join(backend.avisos()) or "no disponible en este sistema"

            def avisar() -> tuple[bool, str]:
                return True, f"inicio automático: {motivo}"

            return [Step("inicio automático (no aplica acá)", [],
                         optional=True, func=avisar)]

        if not enable:
            def quitar() -> tuple[bool, str]:
                return backend.quitar(CORE_AUTOSTART_TASK)

            return [Step("quitar inicio automático", [], optional=True,
                         func=quitar, objetivo=CORE_AUTOSTART_TASK)]

        interprete = self._interprete_de_arranque()
        script = PROJECT_ROOT / "scripts" / "autostart_core.py"
        argv = [str(interprete), str(script)]
        avisos = backend.avisos()

        def instalar() -> tuple[bool, str]:
            ok, detalle = backend.instalar(CORE_AUTOSTART_TASK, argv,
                                           cwd=str(PROJECT_ROOT))
            if ok and avisos:
                # El caso del linger: se instaló bien Y no va a arrancar. Las
                # dos cosas son verdad y hay que decir las dos.
                detalle += ". OJO: " + "; ".join(avisos)
            return ok, detalle

        etiqueta = (f"inicio automático con {backend.sistema} (núcleo)")
        # OPCIONAL, y esto no es un detalle. Los seis servicios ya arrancaron
        # cuando se llega a este paso: si registrar la tarea falla (systemd sin
        # bus, permisos, lo que sea) y el paso fuera obligatorio, el plan se
        # cortaba ACÁ y nunca llegaba a verificar si el núcleo había quedado
        # arriba. Terminabas sin saber lo único que importaba, por culpa de lo
        # que menos importaba.
        return [Step(etiqueta, [], optional=True, func=instalar,
                     objetivo=CORE_AUTOSTART_TASK)]

    # -- planes completos --

    def _pasos_para_levantar(self, clave: str, nombre: str, run: str) -> list[Step]:
        """Los pasos para poner en marcha UNO del núcleo, con sus excusas.

        Cada servicio puede no arrancar por dos motivos distintos y los dos se
        dicen en vez de saltearse: que este equipo no sea el lugar (el proxy en
        un servidor sin escritorio) o que le falte un secreto (el token de
        Secure-Agent). En los dos casos sale un paso que explica; en ninguno
        se lanza un proceso que se va a morir en silencio.
        """
        if clave == "proxy" and not self._corresponde_el_proxy():
            from . import capacidades as mod_cap

            return [self._paso_no_aplica(mod_cap.alcance_del_proxy())]

        falta = self._falta_un_secreto(clave)
        if falta is not None:
            return [falta]

        paso = self._run_script_step(clave, run, f"iniciar {nombre}",
                                     background=True)
        return [paso] if paso else []

    def _corresponde_el_proxy(self) -> bool:
        from . import capacidades as mod_cap

        return mod_cap.alcance_del_proxy()["estado"] != mod_cap.NA

    def _proxy_start_steps(self) -> list[Step]:
        """Prender SecureProxy, salvo donde no sirva.

        Fase 1 del punto 8. En un equipo sin escritorio el proxy no cubre a
        los celulares ni a la consola, porque a esos no hay dónde
        configurarles un proxy. Prenderlo igual sería lo que la regla 10
        prohíbe: una pantalla que parece cobertura y no lo es.

        No se saltea en silencio. Sale un paso que dice por qué no se prendió
        y cuál es la pieza que sí cubre la casa, que es SecureDNS.
        """
        from . import capacidades as mod_cap

        capacidad = mod_cap.alcance_del_proxy()
        if capacidad["estado"] == mod_cap.NA:
            return [self._paso_no_aplica(capacidad)]

        proxy = self._run_script_step("proxy", "scripts/run_proxy.py",
                                      "iniciar SecureProxy", background=True)
        if not proxy:
            return []
        return [proxy] + self._set_system_proxy_steps(True)

    def plan_start_core(self) -> list[Step]:
        steps: list[Step] = []
        # Tomar el control: sacar los autostart propios de cada proyecto.
        steps += self._adopt_ownership_steps()
        # Un solo kill para todos los puertos (una llamada a PowerShell, no una
        # por proyecto).
        kill = self._kill_ports_step(
            list(self._puertos_del_nucleo().values()),
            "liberar puertos del núcleo (instancias previas)",
        )
        if kill:
            steps.append(kill)
        # Los seis, en el orden de la tabla. Cada uno con sus pasos de sistema
        # cuando los tenga: el proxy y el DNS son los únicos que además hay que
        # dejar puestos en la configuración de Windows.
        despues = {"proxy": lambda: self._set_system_proxy_steps(True),
                   "dns": lambda: self._set_system_dns_steps(True)}
        for clave, nombre, run, _stop in SERVICIOS_DEL_NUCLEO:
            steps += self._pasos_para_levantar(clave, nombre, run)
            if clave in despues:
                steps += despues[clave]()
        steps += self._autostart_steps(True)
        # Verificar SIEMPRE, no solo en Windows. Ese `if` era el que hacía que
        # un servicio que arranca y se muere al segundo se viera igual que uno
        # encendido: el plan salía todo en verde y el panel decía "apagado".
        steps.append(self._verify_up_step(
            self._nombres_y_puertos_del_nucleo(), self._nombres_a_claves()))
        return steps

    def _puertos_del_nucleo(self) -> dict[str, int]:
        """Clave de proyecto -> puerto que dice si está vivo.

        Ojo con el proxy: el que importa es el 8888 (por donde proxea) y no el
        de su dashboard. Si escucha el 8888, está proxeando.
        """
        puertos = {
            "proxy": self.cfg.ports.proxy_service,
            "dns": self.cfg.ports.dns_dashboard,
            "hips": self.cfg.ports.hips_dashboard,
            "intel": self.cfg.ports.intel_dashboard,
            "scanner": self.cfg.ports.scanner_dashboard,
            # El de INGESTA, que es el que dice si está vivo.
            "agente": self.cfg.ports.agente_ingesta,
        }
        return {k: puertos[k] for k in CLAVES_DEL_NUCLEO if k in puertos}

    def _nombres_a_claves(self) -> dict:
        """Nombre lindo -> clave de proyecto.

        La verificación muestra nombres ("Secure-Scanner") y necesita la clave
        ("scanner") para saber qué archivo de arranque leer.
        """
        nombres = {s.key: s.display_name for s in PROJECT_SPECS}
        return {nombres.get(k, k): k for k in self._puertos_del_nucleo()}

    def _nombres_y_puertos_del_nucleo(self) -> dict[str, int]:
        """Lo mismo pero con el nombre lindo, que es lo que se muestra."""
        nombres = {s.key: s.display_name for s in PROJECT_SPECS}
        return {
            nombres.get(clave, clave): puerto
            for clave, puerto in self._puertos_del_nucleo().items()
        }

    def plan_stop_core(self) -> list[Step]:
        steps: list[Step] = []
        # Stops 'prolijos' (limpian PID) - rápidos, sin PowerShell.
        #
        # El de SecureHIPS va PRIMERO y no es un lujo: su apagado ordenado
        # saca del firewall las reglas que puso. Si lo matáramos por puerto,
        # esas reglas quedarían puestas sin nadie que las levante cuando
        # venzan, o sea alguien bloqueado para siempre por un programa que ya
        # no corre.
        # De la misma tabla que el encendido, y al revés: el que se prendió
        # primero se apaga último. SecureHIPS va antes que nadie porque su
        # apagado ordenado saca del firewall las reglas que puso.
        orden = ([s for s in SERVICIOS_DEL_NUCLEO if s[0] == "hips"]
                 + [s for s in reversed(SERVICIOS_DEL_NUCLEO) if s[0] != "hips"])
        for key, name, _run, script in orden:
            # Todos en la misma tanda: son seis intérpretes de Python
            # arrancando, cada uno tarda casi lo mismo, y no dependen entre
            # ellos. En fila eran seis arranques sumados; juntos, uno.
            #
            # SecureHIPS igual va primero en la lista, y eso sigue importando:
            # su apagado ordenado saca del firewall las reglas que puso, y el
            # kill por puerto viene DESPUÉS de que terminaron todos.
            stop = self._run_script_step(key, script, f"detener {name} (prolijo)",
                                         background=False, optional=True,
                                         tanda="apagar el núcleo")
            if stop:
                steps.append(stop)
        # Un solo kill robusto para todos los puertos, como red de contención
        # de los stops de arriba.
        kill = self._kill_ports_step(
            list(self._puertos_del_nucleo().values()),
            "asegurar puertos del núcleo cerrados",
        )
        if kill:
            steps.append(kill)
        steps += self._set_system_dns_steps(False)
        steps += self._set_system_proxy_steps(False)
        # Sacar autostart viejos de cada proyecto + el del núcleo.
        task = self._paso_sacar_varios_autostart(
            CLAVES_DEL_NUCLEO, "quitar los autostart viejos de cada proyecto")
        if task:
            steps.append(task)
        steps += self._autostart_steps(False)
        if _is_windows():
            steps.append(self._verify_down_step(self._nombres_y_puertos_del_nucleo()))
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

    def _falta_un_secreto(self, key: str) -> Step | None:
        """Un paso que explica que falta un token, en vez de lanzar y morir.

        Secure-Agent no arranca sin `SECUREAGENT_TOKEN`, y hace bien. El
        problema era otro: se lanza en segundo plano, así que imprimía el
        motivo en una consola que nadie ve, devolvía 1 y se moría. Desde acá
        eso se veía EXACTAMENTE igual que "nunca arrancó", y el panel quedaba
        en "apagado" para siempre sin decir por qué.

        Se mira su `.env` y el entorno antes de lanzar nada. El valor no se lee
        ni se guarda: solo se mira si está y no está vacío.
        """
        requerido = SECRETOS_REQUERIDOS.get(key)
        if not requerido:
            return None
        clave, receta = requerido
        project = self.projects.get(key)
        if project is None or not project.found:
            return None

        if os.environ.get(clave, "").strip():
            return None
        env = project.folder / ".env"
        try:
            for linea in env.read_text(encoding="utf-8", errors="replace").splitlines():
                nombre, _, valor = linea.partition("=")
                if nombre.strip() == clave and valor.strip().strip("\"'"):
                    return None
        except OSError:
            pass

        nombre_bonito = project.spec.display_name
        archivo = project.folder / ".env"
        atajo = self._comando_de_preparar()

        def accion() -> tuple[bool, str]:
            return False, (
                f"{nombre_bonito} no puede arrancar: falta {clave} en "
                f"{archivo} (o el archivo .env no existe). Sin eso el "
                f"proceso arranca, imprime el error y se muere, y desde acá se "
                f"ve igual que si no hubiera arrancado nunca. "
                f"Lo más rápido, desde donde estés:  {atajo}  "
                f"(te genera uno y lo escribe). A mano:  {receta}")

        return Step(f"{nombre_bonito}: falta {clave}", [], optional=True, func=accion)

    def _start_one_core(self, key: str, run_script: str, name: str, port: int, system_steps: list[Step]) -> list[Step]:
        # Antes que nada: si le falta un secreto, no se lanza un proceso que va
        # a morirse en silencio. Se dice qué falta.
        falta = self._falta_un_secreto(key)
        if falta is not None:
            return [falta]

        run = self._run_script_step(key, run_script, f"iniciar {name}", background=True)
        if run is None:
            return []
        steps: list[Step] = []
        kill = self._kill_ports_step([port], f"liberar puerto {port} ({name})")
        if kill:
            steps.append(kill)
        steps.append(run)
        steps += system_steps
        # La verificación corre SIEMPRE y no solo en Windows. Estaba detrás de
        # un `if _is_windows()`, y ese if era el que hacía que un servicio que
        # arranca y se muere al segundo se viera igual que uno encendido: el
        # plan salía todo en verde y el panel decía "apagado".
        steps.append(self._verify_up_step({name: port}, {name: key}))
        return steps

    def _stop_one_core(self, key: str, stop_script: str, name: str, port: int, system_steps: list[Step]) -> list[Step]:
        steps: list[Step] = []
        # Primero se saca el autostart: si la tarea programada lo relanzara
        # justo después de matarlo, el servicio "revive" y parece que apagar
        # no hizo nada.
        task = self._paso_sacar_autostart(key, f"quitar autostart viejo de {name}")
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
            # Acá SÍ se prende aunque no corresponda: el botón es una orden
            # explícita de una persona, no el plan automático. Hay un caso
            # legítimo (mirar qué sale del propio servidor) y negárselo a quien
            # lo pidió a mano sería decidir por él. El aviso lo imprime el
            # propio SecureProxy al arrancar, y la capacidad lo dice en el
            # diagnóstico.
            return self._start_one_core("proxy", "scripts/run_proxy.py", "SecureProxy", self.cfg.ports.proxy_service, self._set_system_proxy_steps(True))
        if key == "dns":
            return self._start_one_core("dns", "scripts/run_dns.py", "SecureDNS", self.cfg.ports.dns_dashboard, self._set_system_dns_steps(True))
        if key == "intel":
            return self._start_one_core("intel", "scripts/run_intel.py", "Secure-Intel", self.cfg.ports.intel_dashboard, [])
        if key == "hips":
            # Sin pasos de configuración del sistema: SecureHIPS no pide que
            # apuntes nada hacia él.
            return self._start_one_core("hips", "scripts/run_hips.py", "SecureHIPS", self.cfg.ports.hips_dashboard, [])
        if key == "scanner":
            # Secure-Scanner no está en el núcleo: escanear la red es algo que
            # se prende aparte, igual que la VPN. Pero desde el panel se tiene
            # que poder, o el botón que ya está dibujado no haría nada.
            return self._start_one_core("scanner", "scripts/run_scanner.py",
                                        "Secure-Scanner",
                                        self.cfg.ports.scanner_dashboard, [])
        if key == "agente":
            # Lo que se prende acá es el SERVIDOR de ingesta, no un agente:
            # los agentes viven en las otras máquinas y se administran solos.
            return self._start_one_core("agente", "scripts/run_servidor.py",
                                        "Secure-Agent (servidor)",
                                        self.cfg.ports.agente_ingesta, [])
        if key == "vpn":
            return self.plan_start_vpn()
        return []

    def plan_stop_one(self, key: str) -> list[Step]:
        if key == "proxy":
            return self._stop_one_core("proxy", "scripts/stop_proxy.py", "SecureProxy", self.cfg.ports.proxy_service, self._set_system_proxy_steps(False))
        if key == "dns":
            return self._stop_one_core("dns", "scripts/stop_dns.py", "SecureDNS", self.cfg.ports.dns_dashboard, self._set_system_dns_steps(False))
        if key == "intel":
            return self._stop_one_core("intel", "scripts/stop_intel.py", "Secure-Intel", self.cfg.ports.intel_dashboard, [])
        if key == "hips":
            return self._stop_one_core("hips", "scripts/stop_hips.py", "SecureHIPS", self.cfg.ports.hips_dashboard, [])
        if key == "scanner":
            return self._stop_one_core("scanner", "scripts/stop_scanner.py",
                                       "Secure-Scanner",
                                       self.cfg.ports.scanner_dashboard, [])
        if key == "agente":
            return self._stop_one_core("agente", "scripts/stop_servidor.py",
                                       "Secure-Agent (servidor)",
                                       self.cfg.ports.agente_ingesta, [])
        if key == "vpn":
            return self.plan_stop_vpn()
        return []

    # ---------------- ejecución ----------------

    @staticmethod
    def _en_tandas(steps: list[Step]) -> list:
        """Agrupa los pasos consecutivos de la misma tanda. NO ejecuta nada.

        Devuelve una lista donde cada elemento es un paso suelto o una lista de
        pasos para correr juntos. Que agrupar y ejecutar sean dos cosas
        distintas es lo que permite probar el agrupado sin lanzar un solo
        proceso, y lo que mantiene el orden del plan: la tanda se corre en su
        lugar, no antes que todo lo demás.

        Solo se agrupan pasos con `argv` (procesos externos). Los pasos que son
        funciones de Python tocan estado compartido y ya son rápidos.
        """
        unidades: list = []
        for paso in steps:
            paralelizable = bool(paso.tanda and paso.func is None and paso.argv)
            if (paralelizable and unidades and isinstance(unidades[-1], list)
                    and unidades[-1][0].tanda == paso.tanda):
                unidades[-1].append(paso)
            elif paralelizable:
                unidades.append([paso])
            else:
                unidades.append(paso)
        # Una "tanda" de uno es un paso normal: no vale la pena el hilo ni el
        # renglón que anuncia el paralelo.
        return [u[0] if isinstance(u, list) and len(u) == 1 else u
                for u in unidades]

    def _correr_tanda(self, grupo: list, emitir) -> None:
        """Lanza el grupo junto y espera a todos.

        Lo que sale se emite DESPUÉS y en el orden del plan, no en el orden en
        que terminaron: un apagado cuyas líneas salen distintas cada vez es
        imposible de comparar con el de la vez anterior.
        """
        from concurrent.futures import ThreadPoolExecutor

        def uno(step: Step):
            lineas: list[str] = []
            codigo = run_streaming(step.argv, cwd=step.cwd, timeout=step.timeout,
                                   on_line=lineas.append)
            return step, codigo, lineas

        emitir(f"> en paralelo: " + ", ".join(s.label for s in grupo) + "...")
        with ThreadPoolExecutor(max_workers=len(grupo)) as pool:
            resultados = list(pool.map(uno, grupo))
        for step, codigo, lineas in resultados:
            for linea in lineas:
                emitir(f"   {linea}")
            if codigo == 0:
                emitir(f"OK: {step.label}")
            elif step.optional:
                emitir(f"omitido (no estaba activo): {step.label}")
            else:
                # No corta el plan: los de la tanda ya corrieron todos, y
                # cortar acá sería fingir que el que falló impidió a los otros.
                emitir(f"ERROR: {step.label} -> devolvió {codigo}")

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
        for unidad in self._en_tandas(steps):
            if isinstance(unidad, list):
                self._correr_tanda(unidad, emitir)
                continue
            step = unidad
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
                    # Un paso interno obligatorio tiene la misma semántica
                    # que un subprocess obligatorio: si falló, seguir con el
                    # plan puede dejar el sistema en un estado incoherente
                    # (por ejemplo iniciar un servicio sin haber liberado su
                    # puerto). Antes se marcaba el error pero se continuaba.
                    break
                continue

            try:
                if step.background:
                    popen_quiet(step.argv, cwd=step.cwd, log=step.log)
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
