"""Quiénes entran al núcleo, y por qué los dos últimos son un caso aparte.

EL NÚCLEO SIEMPRE FUE "LO QUE NO MOLESTA PRENDIDO TODO EL DÍA"

SecureProxy, SecureDNS, SecureHIPS y Secure-Intel filtran y miran. Podés
tenerlos arriba todo el día y no te enterás. La VPN quedó afuera porque mete
todo tu tráfico por un túnel y te puede cortar una partida.

Secure-Scanner y Secure-Agent quedaron afuera por la misma clase de razón, y
mirándolo de nuevo esa razón solo es buena para uno de los dos.

SECURE-AGENT: TENERLO APAGADO PIERDE DATOS PARA SIEMPRE

Es un receptor. No hace nada, espera. Y los agentes que corren en las otras
máquinas empujan y no guardan cola en disco, a propósito: la telemetría es una
foto de AHORA, y mandar dentro de dos horas lo que había hace dos horas ensucia
el estado del servidor con cosas que ya no son ciertas.

O sea que cada minuto que el servidor está apagado es telemetría que se pierde
y no se recupera. Eso no es "algo que prendés cuando lo querés": es algo que si
lo configuraste, querés arriba.

Lo que sí es cierto es que abre un puerto a la LAN. Pero esa decisión ya la
tomaste cuando pusiste el token: sin token no arranca, y esa es la puerta.

SECURE-SCANNER: DEPENDE DE ALGO QUE SE PUEDE VERIFICAR

Acá el argumento en contra es real: manda paquetes a equipos que no son tuyos.
Si el rango está mal, le estás escaneando puertos al televisor del vecino.

Pero el argumento a favor también es real, y es el que casi se me pasa: la
tabla de novedades ("apareció un equipo nuevo", "este se fue") **solo
significa algo si se mira seguido**. Un escaneo cuando te acordás no detecta
que apareció algo el martes: detecta que hoy hay algo que la última vez no
estaba, y la última vez fue hace tres semanas.

Así que la pregunta no es "¿prender o no?" sino "¿está apuntando al lugar
correcto?". Y eso se puede verificar: si el rango está escrito a mano en su
configuración, alguien lo decidió. Si está vacío, lo autodetecta, y autodetectar
puede agarrar la red equivocada en una máquina con VPN, Docker o dos placas.

LA REGLA, ENTONCES

Cada uno entra al núcleo si está CONFIGURADO, y "configurado" quiere decir algo
concreto y verificable para cada uno. Cuando no entra, no se saltea callado: el
plan saca un paso que dice por qué y qué falta.

Y se puede forzar en los dos sentidos desde `config.yaml`, porque esto es una
decisión de quien lo usa y no mía.
"""

from pathlib import Path

# Los que pueden entrar o no. Los otros cuatro entran siempre.
EXTRAS = ("agente", "scanner")

AUTO, SI, NO = "auto", "si", "no"
ELECCIONES = (AUTO, SI, NO)


def _config_del_proyecto(project) -> dict:
    """El `config/config.yaml` de otro proyecto. Vacío si no se puede leer.

    Se lee y no se importa su código: SecureCenter orquesta, no depende de los
    módulos de nadie. Un YAML roto o ausente devuelve vacío y el que llama
    decide qué significa eso.
    """
    if project is None or not getattr(project, "found", False):
        return {}
    try:
        import yaml

        crudo = (Path(project.folder) / "config" / "config.yaml").read_text(
            encoding="utf-8", errors="replace")
        datos = yaml.safe_load(crudo) or {}
    except Exception:  # noqa: BLE001 - leer la config de otro no puede romper esto
        return {}
    return datos if isinstance(datos, dict) else {}


def _hay_token(project, clave: str = "SECUREAGENT_TOKEN") -> bool:
    """Si el `.env` del proyecto (o el entorno) tiene esa clave con valor.

    El valor no se lee ni se guarda: solo se mira si está y no está vacío.
    """
    import os

    if os.environ.get(clave, "").strip():
        return True
    if project is None or not getattr(project, "found", False):
        return False
    try:
        texto = (Path(project.folder) / ".env").read_text(
            encoding="utf-8", errors="replace")
    except OSError:
        return False
    for linea in texto.splitlines():
        nombre, _, valor = linea.partition("=")
        if nombre.strip() == clave and valor.strip().strip("\"'"):
            return True
    return False


def _entra_el_agente(project) -> tuple[bool, str]:
    if not _hay_token(project):
        return False, ("no tiene SECUREAGENT_TOKEN en su .env. Sin token no "
                       "arranca (un token por defecto es un token público), "
                       "así que tampoco tiene sentido prenderlo con el núcleo")
    datos = _config_del_proyecto(project)
    servidor = datos.get("servidor") or {}
    if isinstance(servidor, dict) and servidor.get("habilitado") is False:
        return False, ("su config.yaml lo tiene apagado (servidor.habilitado: "
                       "false). Esta máquina no es el servidor de ingesta")
    return True, ""


def _entra_el_scanner(project) -> tuple[bool, str]:
    datos = _config_del_proyecto(project)
    red = datos.get("red") or {}
    rango = str((red.get("rango") if isinstance(red, dict) else "") or "").strip()
    if not rango:
        return False, ("no tiene rango fijado en su config.yaml, así que lo "
                       "autodetecta. Autodetectar puede agarrar la red "
                       "equivocada en una máquina con VPN, Docker o dos "
                       "placas, y escanear la red equivocada es mandarle "
                       "paquetes a equipos que no son tuyos")
    return True, f"rango fijado: {rango}"


PUERTAS = {"agente": _entra_el_agente, "scanner": _entra_el_scanner}


def evaluar(projects: dict, preferencias=None) -> dict:
    """{clave: (entra, motivo)} para los dos opcionales.

    `preferencias` es el objeto `NucleoConfig` de la configuración: cada clave
    puede ser "auto" (decide la puerta), "si" (entra igual) o "no" (no entra).
    Forzar existe porque esto es una decisión de quien lo usa; lo que no se
    puede es que la decisión sea invisible.
    """
    salida = {}
    for clave in EXTRAS:
        project = projects.get(clave)
        if project is None or not getattr(project, "found", False):
            # No está instalado. No es una decisión, es un dato, y no genera
            # ningún paso: nadie tiene que enterarse de que no tiene un
            # proyecto que nunca clonó.
            continue
        eleccion = str(getattr(preferencias, clave, AUTO) or AUTO).lower()
        if eleccion == NO:
            salida[clave] = (False, "lo dejaste afuera del núcleo en config.yaml")
            continue
        entra, motivo = PUERTAS[clave](project)
        if eleccion == SI:
            salida[clave] = (True, "forzado en config.yaml" if not entra else motivo)
            continue
        salida[clave] = (entra, motivo)
    return salida


def los_que_entran(projects: dict, preferencias=None) -> list:
    return [clave for clave, (entra, _m) in evaluar(projects, preferencias).items()
            if entra]
