"""Cliente del endpoint de bloqueo de SecureHIPS.

Es el mismo camino que ya usa SecureProxy, con la misma idea de fondo: el que
detecta pide, y el que bloquea decide. SecureHIPS es el único que escribe en el
firewall, desde su ADR 0006.

DOS DETALLES QUE NO SON DETALLES

- **Se saltea el proxy del sistema.** Cuando el núcleo está prendido, el proxy
  del sistema es SecureProxy. Un `urlopen` normal mandaría este pedido a
  `127.0.0.1:8892` a través de él, o sea que SecureCenter le hablaría al HIPS
  pasando por el proxy que él mismo prendió. `ProxyHandler({})` corta eso.

- **El token sale del `.env`, nunca del YAML.** Es la regla de toda la suite.
  Y es el MISMO string que tiene SecureHIPS en el suyo: no hay un mecanismo de
  intercambio de credenciales, se copia a mano una vez, y eso está escrito
  también en el README para que nadie lo busque.

QUÉ PASA SI EL HIPS NO ESTÁ

Se devuelve que no se bloqueó, y por qué. No hay camino de respaldo: escribir
la regla desde acá sería darle un segundo dueño al firewall justo cuando el
primero está apagado, que es cuando menos se mira. Es el mismo error que se le
sacó a SecureProxy en el punto 8.
"""

import json
import urllib.error
import urllib.request

# Este pedido sale de un click, no del camino de una conexión, así que puede
# esperar un poco más que el del proxy. Sigue siendo localhost.
TIMEOUT = 5.0


class ClienteHIPS:
    """Le pide bloqueos a SecureHIPS. No escribe ninguna regla."""

    def __init__(self, url: str = "", token: str = "", timeout: float = TIMEOUT):
        self.url = (url or "").strip().rstrip("/")
        self.token = (token or "").strip()
        self.timeout = float(timeout)
        self.aceptados = 0
        self.rechazados = 0
        self.ultimo_error = ""

    def configurado(self) -> bool:
        return bool(self.url and self.token)

    def por_que_no(self) -> str:
        if not self.url:
            return "no tiene dirección configurada (ports.hips_dashboard)"
        if not self.token:
            return ("no tiene token: falta SECUREHIPS_API_TOKEN en el .env de "
                    "SecureCenter, con el mismo valor que el de SecureHIPS")
        return ""

    def bloquear(self, ip: str, motivo: str = "",
                 duracion: int | None = None) -> tuple[bool, str]:
        """Pide el bloqueo. Devuelve (el HIPS lo tomó, qué contestó).

        `False` no significa "error grave": significa "no pasó nada y acá está
        el motivo". El que llama tiene que poder mostrarlo tal cual.
        """
        if not self.configurado():
            return False, f"SecureHIPS {self.por_que_no()}"

        cuerpo = {"ip": ip, "origen": "securecenter", "motivo": motivo}
        if duracion:
            cuerpo["duracion"] = int(duracion)
        pedido = urllib.request.Request(
            f"{self.url}/api/bloquear", data=json.dumps(cuerpo).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json",
                     # En un header y no en la URL: una URL con el token
                     # adentro termina en los logs y en el historial.
                     "Authorization": f"Bearer {self.token}"})
        abridor = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with abridor.open(pedido, timeout=self.timeout) as respuesta:
                datos = json.loads(respuesta.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as exc:
            self.rechazados += 1
            self.ultimo_error = f"HTTP {exc.code}"
            return False, f"SecureHIPS rechazó el pedido (HTTP {exc.code})"
        except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
            self.rechazados += 1
            self.ultimo_error = str(exc)
            return False, f"no pude hablar con SecureHIPS: {exc}"

        if not datos.get("ok"):
            # El caso más valioso de todos: la IP está en la lista blanca del
            # HIPS. Se muestra tal cual y NO se insiste por otro camino, porque
            # insistir sería saltearse la lista blanca.
            self.rechazados += 1
            razon = datos.get("razon") or datos.get("error") or "sin detalle"
            return False, f"SecureHIPS no la bloqueó: {razon}"

        self.aceptados += 1
        if datos.get("aplicado"):
            return True, f"SecureHIPS bloqueó {ip} por 4 horas"
        return True, (f"SecureHIPS registró el pedido pero NO bloqueó: está en "
                      f"modo {datos.get('modo') or 'audit'}")


def desde_config(cfg) -> ClienteHIPS:
    """El cliente armado con lo que hay en la configuración y en el entorno."""
    import os

    puerto = getattr(getattr(cfg, "ports", None), "hips_dashboard", 0) or 8892
    return ClienteHIPS(url=f"http://127.0.0.1:{puerto}",
                       token=os.getenv("SECUREHIPS_API_TOKEN", ""))
