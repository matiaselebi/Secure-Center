# ADR 0002: Suricata mira, SecureHIPS aplica

Fecha: 2026-08

Estado: aceptado (las cuatro fases)

## Contexto

Toda la suite mira la red desde arriba. SecureDNS ve el nombre que se
consultó. SecureProxy ve la conexión que abrió un proceso, con qué ritmo y
cuánto transfirió. SecureHIPS ve quién golpea la puerta. Secure-Agent ve el
proceso adentro de cada máquina.

Ninguno ve el paquete. Suricata sí: reconoce el certificado de una familia de
malware en el handshake de TLS, el User-Agent crudo de un pedido HTTP, un
patrón de bytes que corresponde a un exploit conocido en un puerto donde no
debería estar pasando eso. Son cosas que no se deducen de un nombre ni de un
par de IPs.

También es, de lejos, la pieza más pesada de todas. Con el ruleset abierto de
Emerging Threats el árbol de reglas solo pasa el giga de RAM, y arriba están
las tablas de flujos, que crecen con el tráfico. En el equipo equivocado no es
que anda lento: se queda sin memoria, y el que muere es el proceso más gordo,
que puede ser Pi-hole. Por eso el punto se llama "solo si el hardware
aguanta".

## Decisiones

### 1. Solo detección. Nunca en línea.

Suricata se levanta con `af-packet`, mirando una copia del tráfico. No se
engancha a NFQUEUE ni se usa `copy-mode: ips`.

El motivo no es estético. En modo IPS los paquetes pasan **por** Suricata, así
que una regla del ruleset abierto puede cortarte internet en tu propia casa, y
el que escribió esa regla no te conoce ni sabe qué usás. Un falso positivo
dejó de ser un renglón en una pantalla y pasó a ser el Netflix que no abre.

El que bloquea es SecureHIPS, y es el único, desde el ADR 0006 de ese
proyecto. Tiene vencimiento, escalera de duraciones, lista blanca, país,
motivo registrado y un botón para levantar el bloqueo. Una regla de Suricata
cortando por su cuenta no tiene nada de eso: bloquea para siempre, sin fila en
ninguna base que diga por qué.

Esto se **verifica**, no se confía: `revisar_modo()` mira la línea de comando
del proceso que está corriendo. Se lee de `/proc` y no del `suricata.yaml`
porque el archivo que trae el paquete viene con la sección de NFQUEUE escrita
y comentada, como ejemplo; buscar esas palabras en el texto diría "modo IPS"
en una instalación recién hecha que no lo está. Cuando hay que mirar el YAML
(para el `copy-mode`), se lo parsea, porque un parser ignora los comentarios.

Lo que está corriendo es un hecho. Lo que dice un archivo de configuración es
una intención, y encima puede estar comentada.

### 2. Vive en SecureCenter, no es un proyecto nuevo

Suricata tiene la misma forma que Pi-hole: un motor instalado en el sistema,
sin carpeta hermana, sin venv, sin script de arranque. Ya hay un lugar para
eso, que es `externos` en la configuración, con la ruta absoluta a su salida.

Un `secure-ids` propio sería una carpeta más para mantener toda la vida y no
tendría nada adentro: Suricata detecta, y lo único que hace falta de este lado
es traducir lo que escribe al modelo común. Eso son doscientas líneas, no un
proyecto.

Tampoco va adentro de SecureHIPS, que sería la otra opción razonable ya que
tiene CrowdSec abajo. El `eve.json` de un gateway con tráfico real crece a
cientos de megas por día, y meter ese parseo en el proceso que tiene el
firewall en la mano es cargarlo de trabajo que no es suyo. SecureHIPS aplica.
Detect lee y correlaciona.

### 3. Metadata, nunca captura completa

Los campos que se copian de una alerta son una **lista blanca** escrita en
`suricata.py`, no una lista negra.

Una alerta de `eve.json` puede traer `payload` y `payload_printable` (el
contenido del paquete, en base64 y en texto plano), `packet` entero, y el
cuerpo de un pedido HTTP. Adentro va la contraseña que alguien escribió en un
formulario, el token de sesión de su banco, el contenido de un mail. Que eso
termine en una base SQLite que se abre desde un panel web es convertir la
herramienta de seguridad en el problema.

Con lista negra, el día que Suricata agregue un campo nuevo con contenido,
entraría solo y nadie se enteraría. Con lista blanca no entra nada que no esté
escrito. Hay un test que arma una alerta con contraseña adentro y verifica que
esa cadena no aparezca en ningún lado del evento resultante.

**Y hace falta la otra mitad, que es la fase 3.** Mientras esas opciones estén
prendidas del lado de Suricata, el dato igual se escribe en `eve.json`, que
queda en el disco del gateway, entra en los backups y lo lee cualquiera que
tenga una shell ahí. Filtrarlo al leerlo no lo borra del disco.

Así que se revisa también la configuración de Suricata: `payload`,
`payload-printable`, `packet`, `http-body`, `http-body-printable` y
`tagged-packets` tienen que estar en `no`, y `pcap-log` y `file-store`
apagados. Lo único que se quiere prendido de esa familia es `metadata: yes`,
que trae de qué familia de malware es la firma.

Se revisa y no se corrige: `suricata.yaml` no es nuestro archivo y tocarlo
necesita root. El diagnóstico dice el cambio exacto, y en `docs/` está el
fragmento listo para pegar, con un test que verifica que ese fragmento pase la
misma revisión que corre el diagnóstico. Un ejemplo de la documentación que el
propio programa marcaría como mal es peor que no tener ejemplo.

### 4. Se lee la cola del archivo, sin marca de agua

`eve.json` se lee desde el final, con un tope de 2 MB por vez. No hay offset
guardado, y es a propósito: el archivo **rota**, y un offset guardado después
de una rotación apunta a cualquier lado. Además es la misma semántica que
tienen todos los otros adaptadores ("los últimos N eventos").

La contracara es honesta y está probada: una alerta vieja enterrada bajo megas
de tráfico posterior no se ve.

### 5. Las alertas entran como un tipo propio

`alerta_red`, no `conexion_bloqueada`. En modo detección no se bloqueó nada:
es una opinión sobre tráfico que pasó, no una acción. Mezclarla con los
bloqueos haría que el panel diga que se cortaron conexiones que nunca se
cortaron.

Sí cuenta como "alguna herramienta señaló esto" para las reglas de
correlación, y la palabra que lo justifica ya estaba escrita en ellas: dicen
"señalada", no "bloqueada". Reconocer la firma de un troyano adentro del
paquete es señalar, y de los más fuertes que hay.

Esa lista de tipos estaba copiada en tres reglas distintas. Al entrar Suricata
se extrajo a una constante única (`TIPOS_QUE_SENALAN`), porque olvidarse de
uno de los tres lugares no rompe ningún test: solo hace que una regla vea
menos que las otras, para siempre, sin que nadie se entere.

## Consecuencias

- Suricata es **opcional**. Sin él la suite funciona entera, con menos
  visibilidad de red. Cuando no está instalado, el diagnóstico saca una sola
  fila que lo dice, y no cuatro renglones grises sobre algo que elegiste no
  instalar.
- El diagnóstico ahora puede decir que el equipo **no da**, con el número de
  RAM y de núcleos de esta máquina en la fila. Ese número no reemplaza medir
  con tráfico real: es el piso por debajo del cual no vale la pena intentar.
- Una alerta de Suricata sola no arma un incidente. Hace falta que otra
  herramienta coincida en el mismo indicador, que es la regla de siempre.

## Fase 4: Detect puede pedir un bloqueo, apretando un botón

Es el primer lugar donde SecureCenter puede cambiar algo del sistema. Hasta
acá solo miraba: leía bases, cruzaba indicadores y armaba incidentes. Por eso
llegó último, y por eso es un **botón** y no una automatización.

La hoja de ruta dice "que Detect **pueda** pedirle un bloqueo", y la palabra es
esa. Una alerta de red que bloquea sola es exactamente lo que la fase 1 evitó
al no dejar a Suricata en modo IPS: una regla escrita por alguien que no te
conoce, cortando tráfico tuyo a las tres de la mañana, sin que nadie pueda
relacionar el corte con la causa. Con un botón hay una persona que miró la
evidencia y decidió.

### La trampa que la política existe para evitar

Una alerta de Suricata trae **dos IPs, y una de las dos es tuya**. En una
alerta de comando-y-control saliente, el origen es tu propia PC: es tu máquina
la que está infectada y le habla al servidor de afuera. Bloquear el origen ahí
dejaría sin internet al equipo que quisiste proteger, que es justamente el que
más necesita poder actualizarse, y el implante seguiría adentro igual.

Por eso el trabajo de `respuesta.py` no es mandar el pedido (eso son diez
líneas) sino elegir bien qué IP, y negarse cuando no hay una buena:

- **Nunca una IP privada, de loopback o link-local.** Es la regla de arriba.
- **Nunca un nombre.** El firewall bloquea direcciones; los nombres los bloquea
  SecureDNS. La negativa lo dice y manda ahí, en vez de solo decir que no.
- **Nunca con una sola fuente ni con gravedad baja.** Un incidente armado por
  una sola coincidencia es justamente el que suele estar equivocado, y bloquear
  por uno de esos es cómo se aprende a desconfiar del propio panel.

Cuando no se puede, el motivo aparece **en el lugar donde estaría el botón**.
Un botón que falta sin explicación hace creer que el programa está roto.

### Lo demás

El bloqueo pedido desde acá dura **cuatro horas**, bastante menos que la
escalera propia de SecureHIPS. Lo pidió una persona mirando una pantalla, no un
detector que contó cinco intentos fallidos de login. Si la IP es mala de
verdad va a volver y se puede repetir; si fue un error, se cae solo antes de
que alguien tenga que acordarse de sacarlo.

El motivo que queda guardado lleva el nombre de la regla y las herramientas que
coincidieron. Dentro de tres semanas, esa frase es todo lo que va a haber en la
lista de bloqueos de SecureHIPS para entender por qué esa IP está ahí.

Si SecureHIPS contesta que **no** la bloquea porque está en su lista blanca, se
muestra tal cual y no se insiste por ningún otro camino: insistir sería
saltearse la lista blanca. Y si el HIPS no está, no se bloquea nada y se dice.
No hay respaldo que escriba la regla desde acá, porque eso le daría un segundo
dueño al firewall justo cuando el primero está apagado, que es cuando menos se
mira. Es el mismo error que se le sacó a SecureProxy en el punto 8.

El token sale del `.env` de SecureCenter y tiene que ser el mismo string que el
de SecureHIPS. Se copia a mano una vez. No tenerlo no rompe nada: deja el botón
apagado con el motivo escrito.
