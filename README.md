# SecureCenter

![CI](https://github.com/matiaselebi/secure-center/actions/workflows/ci.yml/badge.svg)

Centro de control unificado del stack personal de seguridad:
[SecureProxy](https://github.com/matiaselebi/secure-proxy) (filtro de
conexiones), [SecureDNS](https://github.com/matiaselebi/secure-dns) (filtro de
nombres) y [SecureVPN](https://github.com/matiaselebi/secure-vpn) (transporte
cifrado). Un panel y un dashboard únicos para prender, apagar y ver los tres
desde un solo lugar.

**No reimplementa nada de los tres**: los orquesta llamando a sus propios
scripts ([ADR 0001](docs/adr/0001-orquestar-no-reimplementar.md)). Cada
proyecto sigue siendo la fuente de verdad de sí mismo.

## Qué hace

- **Enciende el núcleo (SecureProxy + SecureDNS) con un botón**, y lo deja
  arrancando solo en cada inicio de Windows. Es el "siempre prendido": estos
  dos filtran nombres y conexiones sin afectar juegos ni streaming.
- **Enciende la VPN en un solo paso** (botón aparte): si Docker Desktop está
  cerrado lo abre y espera a que arranque, levanta el laboratorio, aprovisiona
  el servidor y conecta el túnel. La VPN queda **separada del núcleo a
  propósito** - no se prende sola, para que nunca te corte un juego sin
  querer.
- **Apaga TODO con un botón**: núcleo y, si estaba corriendo, también la VPN
  (túnel, kill switch y laboratorio). Si la VPN no se había prendido, omite
  esa parte pero igual cierra el núcleo y le quita el inicio automático.
- **Dashboard unificado** (`http://127.0.0.1:8899/`): una barra global con la
  salud de los tres y los botones globales, un apartado por proyecto con sus
  controles individuales (iniciar/parar ese servicio solo) y un link a su
  propio dashboard, y una **línea de tiempo** que mezcla los eventos de los
  tres (bloqueos de DNS, de proxy, conexiones de VPN) ordenados por hora.
- **Consola en vivo**: apretás un botón y la salida aparece arriba línea por
  línea, a medida que ocurre - incluida la de los scripts de cada proyecto
  mientras corren. Al terminar, ese mismo bloque queda verde si salió bien o
  rojo si falló, con el detalle completo. Encender la VPN puede tardar
  minutos (arranca Docker, construye el laboratorio, aprovisiona por SSH):
  ver el avance es la diferencia entre "está trabajando" y "se colgó".
- **Salud de tres estados, no de dos**: `activo`, `apagado` y `parcial`. La
  diferencia importa: la VPN puede tener su dashboard corriendo y el túnel
  caído, y llamar a eso "activo" sería mentir. Por eso el estado de la VPN se
  consulta a su endpoint `/state`, que dice si hay handshake, y no al puerto
  de su página.
- **Todo lo que apaga, lo verifica**: en vez de confiar en archivos de PID
  (que quedan viejos cuando hubo dos instancias), libera el puerto y después
  chequea que efectivamente haya quedado libre. Si no pudo, lo dice en vez de
  reportar un éxito falso.
- **Pide permisos cuando le hacen falta**: el núcleo se enciende desde el
  `.bat`, que se auto-eleva, así que SecureProxy y SecureDNS quedan
  corriendo como administrador; pero el dashboard arranca con Windows sin
  elevar y no puede matarlos. En vez de fallar, levanta UNA ventana de UAC
  y termina el trabajo.
- **Botón de pánico**: revierte el firewall/kill switch de la VPN y apaga
  todo, incondicionalmente, para cuando algo quedó a medias.
- **Autodetección**: encuentra los tres proyectos entre las carpetas
  hermanas sin importar cómo se llamen (los reconoce por su paquete). Rutas
  configurables en `config/config.yaml` si están en otro lado.
- **Panel `SecureCenter.bat`** con auto-elevación, las mismas acciones que el
  dashboard para quienes prefieren la consola.

## Qué NO hace

- **No reimplementa ni modifica** a SecureProxy, SecureDNS ni SecureVPN: solo
  ejecuta sus scripts. Si borrás SecureCenter, los tres siguen funcionando
  igual por su cuenta.
- **No prende la VPN automáticamente**: siempre es una acción explícita tuya,
  para no interferir con juegos/streaming (ver la nota de abajo).
- **No inventa lógica de seguridad nueva**: el filtrado, el cifrado y el kill
  switch viven en cada proyecto; acá solo se coordinan.

## Por qué la VPN va separada del núcleo

SecureProxy y SecureDNS filtran a nivel de nombres y conexiones: podés
tenerlos prendidos todo el día sin que se note. La VPN, en cambio, mete todo
tu tráfico por un túnel - y en modo laboratorio (servidor dentro de tu PC)
eso rompe cosas sensibles al NAT como juegos online. Por eso el núcleo es
"siempre prendido" y la VPN es un botón aparte que encendés cuando la querés.

## Estructura

```
secure-center/
├── README.md
├── requirements.txt
├── config/config.yaml          # rutas a los 3 proyectos (o autodetección) + puertos
├── data/                        # su propia base de eventos (fuera de git)
├── src/securecenter/
│   ├── config_loader.py
│   ├── projects.py              # modelo + autodetección de los 3 proyectos
│   ├── procutil.py              # puertos, procesos y subprocesos sin ventanas
│   ├── health.py                # estado real de cada uno (activo/parcial/apagado)
│   ├── logs.py                  # línea de tiempo unificada (lee las 3 SQLite en solo-lectura)
│   ├── orchestrator.py          # arma y ejecuta los planes de encendido/apagado
│   ├── logger_db.py             # eventos de orquestación
│   └── dashboard.py             # dashboard unificado (puerto 8899)
├── scripts/
│   ├── start_core.py / stop_all.py
│   ├── start_vpn.py / stop_vpn.py / panic.py
│   ├── autostart_core.py        # relanza el núcleo en cada inicio de Windows
│   ├── stop_dashboards.py       # cierra solo las páginas, no los servicios
│   └── run_dashboard.py / stop_dashboard.py
├── SecureCenter.bat
├── docs/adr/
├── tests/
└── .github/                     # CI + Dependabot
```

## Requisitos

- Los tres proyectos ya instalados y funcionando, **cada uno con su propio
  `venv`** (SecureCenter usa el Python de cada venv para correr sus scripts).
- Guardados en la misma carpeta de proyectos que SecureCenter (carpetas
  hermanas), o con sus rutas puestas en `config/config.yaml`.
- Python 3.11+ y el `venv` propio de SecureCenter.

## Instalación

```powershell
git clone https://github.com/matiaselebi/secure-center.git
cd secure-center
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Uso

Con `SecureCenter.bat` (pide admin solo, lo necesita para el DNS del sistema,
el inicio automático y el firewall del kill switch de la VPN):

1. **Encender núcleo** - prende SecureProxy + SecureDNS, los deja con inicio
   automático, y abre el dashboard unificado.
2. **Apagar todo** - cierra núcleo + VPN (si estaba) + inicio automático.
3. **Encender VPN** - el flujo completo en un paso (abrir Docker si hace
   falta → laboratorio → aprovisionar → conectar).
4. **Apagar VPN** - solo la VPN.
5. **Ver estado** - salud de los cuatro (los tres + SecureCenter).
6. **Abrir dashboard unificado**.
7. **Apagar dashboards** - cierra solo las páginas web. El filtrado y el
   túnel siguen andando: es para cuando querés dejar de tener servidores
   HTTP escuchando pero no apagar la protección.
8. **PÁNICO** - revierte el firewall y el kill switch y apaga todo,
   incondicionalmente.
9. **Salir**.

Todo eso también está en el dashboard (`http://127.0.0.1:8899/`), con control
individual de cada servicio además de los botones globales, y con un diálogo
de confirmación antes de cada acción que cambia el estado del sistema.

### El encendido de la VPN es un solo script

SecureCenter no encadena "levantar laboratorio", "aprovisionar" y "conectar"
por su cuenta: llama a `scripts/start_vpn.py` del proyecto VPN, que hace las
tres cosas con las esperas adentro. Encadenarlas desde acá producía fallas de
carrera -cada script arrancaba apenas terminaba el anterior, sin darle tiempo
al contenedor a tener red ni a `sshd` a aceptar sesiones- que aparecían solo
al encender desde el dashboard y no desde el menú, donde el tiempo que tarda
una persona en apretar la opción siguiente alcanzaba como espera. Ese paso
tiene un timeout de 20 minutos porque la primera vez incluye arrancar Docker
Desktop y construir la imagen del laboratorio.

## Tests

```bash
pytest tests/ -v
```

**78 tests, todos verdes.** Cobertura: autodetección de proyectos (por
paquete, no por nombre de carpeta), chequeo de salud y sus tres estados (que
la VPN con el túnel caído no figure como activa), utilidades de puertos y procesos (incluido el pedido de permisos
cuando un proceso elevado no se deja matar, con un solo cartel de UAC para
todos), línea de tiempo unificada (mezcla y orden de las tres bases SQLite,
tolerando las que no existen), construcción de los planes de orquestación
(núcleo enciende proceso antes de apuntar el sistema; la VPN se enciende con
un solo script y con timeout largo; apagar todo incluye u omite la VPN según
corresponda; pánico restaura internet primero; pasos de apagado tolerantes a
"no estaba corriendo"), apagado verificado de punta a punta, autostart, y el
dashboard (render de los tres apartados + barra global, endpoints,
operaciones en segundo plano de a una por vez, y la consola en vivo: que la
salida se vea mientras la operación corre, que quede ámbar mientras trabaja y
verde o roja al terminar).

Los planes se construyen como pasos inspeccionables en dry-run, así se
testean sin ejecutar procesos reales. La ejecución real sobre Windows (tareas
programadas, DNS del sistema, WireGuard) se prueba en la máquina.

## Roadmap

- Métricas en la barra global (cuántas amenazas bloqueó hoy cada uno).
- Perfiles ("modo trabajo" = núcleo; "modo privacidad" = núcleo + VPN).
- Contenerizar el stack completo para demo/CI en un solo docker-compose.

## Aviso

Proyecto educativo/de portfolio. SecureCenter coordina; la seguridad la
aportan los tres proyectos que orquesta.

## Autor

Matias Elebi - [LinkedIn](https://www.linkedin.com/in/matiaselebi/) · [GitHub](https://github.com/matiaselebi)

## Licencia

MIT
