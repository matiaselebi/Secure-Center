# El Debian como router de la casa

**Opcional, al final, y reversible.** Las tres palabras están en la hoja de
ruta y las tres son parte del diseño, no advertencias de cortesía.

Las tres fases están acá: dejarlo configurado y verificable, probarlo con **un**
dispositivo, y tener el plan de salida escrito **y probado**.

## Por qué esto no es un proyecto

El punto lo dice en una línea: *configuración, no un repo: no armes un
Secure-Router*. La razón se ve mejor al revés.

Un programa que te configura el gateway tiene que saber tus interfaces, tu
rango de IPs y tu proveedor, y tiene que manejar el caso en que algo se corte a
mitad de camino. El día que algo se rompa vas a estar depurando **dos** cosas:
la red, y el programa que la configuró. Y para deshacerlo vas a depender de que
ese programa tenga bien escrito el camino de vuelta.

Cuatro archivos en `gateway/` son cuatro archivos que se copian, se leen
enteros en un minuto, y se borran para volver atrás.

Lo que sí hace SecureCenter es **verificar**: `src/securecenter/gateway.py`
mira y reporta en el diagnóstico, con el mismo formato que el resto. No escribe
una regla, no prende un sysctl, no toca una interfaz. Hay un test que lo
comprueba leyendo el código: los `nft` que aparecen tienen que ser de lectura.

## Lo que cambia de verdad

Antes de tocar nada, lo que hay que tener claro:

**Esta máquina pasa a ser un punto único de falla.** Si se apaga, se cuelga o
se queda sin disco, la casa entera se queda sin internet. Antes era solo este
equipo. El que lo vaya a arreglar un domingo puede no ser el que lo configuró,
así que la fase 3 (el plan de salida) no es opcional.

**Lo que se gana** es que el filtrado deja de depender de que cada equipo esté
configurado. El celular, el televisor y la consola no tienen dónde ponerles un
proxy, pero sí pasan por el router. Es la misma razón por la que SecureProxy se
queda en el escritorio y SecureDNS va en el servidor.

## El diagrama, en dos líneas

```
Antes:   [ módem ] ── wifi ── [ celular, tele, PC, consola ]
                  └── cable ─ [ Debian: Pi-hole + suite ]

Después: [ módem ] ── eth0 ── [ Debian: router + Pi-hole + suite ] ── eth1 ── [ switch ] ── todo lo demás
```

Hace falta una segunda interfaz de red. Un adaptador USB-Ethernet barato
alcanza para un enlace hogareño; un puerto de gigabit real es mejor si vas a
mover archivos entre equipos.

## Los cuatro archivos

Están en la carpeta `gateway/` de este proyecto. Todos empiezan diciendo dónde
van y cómo se sacan.

| Archivo | Dónde va | Qué hace |
|---|---|---|
| `99-gateway.conf` | `/etc/sysctl.d/` | prende el reenvío de paquetes |
| `10-lan.network` | `/etc/systemd/network/` | IP fija en la interfaz de la casa |
| `nftables-gateway.conf` | `/etc/nftables.d/gateway.conf` | NAT y política de reenvío |
| `dnsmasq-gateway.conf` | `/etc/dnsmasq.d/gateway.conf` | DHCP: reparte IP, router y DNS |

Ninguno edita un archivo del sistema en el medio. Todos son archivos nuevos en
carpetas `.d/`, y por eso revertir es borrar y recargar. Editar
`/etc/sysctl.conf` a mano sería más corto y sería peor: dentro de seis meses no
vas a saber cuál línea pusiste vos, y una actualización del sistema puede
tocar ese archivo.

### El orden importa

1. **sysctl primero.** Sin `ip_forward = 1` todo lo demás puede estar perfecto
   y no pasar absolutamente nada. Es el error más común y el más frustrante,
   porque no da ningún mensaje.
2. **La IP fija de la LAN.** Es la puerta de enlace que van a tener escritos
   todos los equipos: si cambia, la casa se queda sin internet.
3. **nftables.** Probá la sintaxis antes de aplicar: `sudo nft -c -f archivo`.
4. **El DHCP al final**, y recién ahí apagás el DHCP del router del proveedor.
   Dos servidores de DHCP en la misma red contestan los dos, gana el que
   contesta más rápido, y el resultado cambia de un arranque a otro. Es de los
   problemas más difíciles de diagnosticar que existen en una red chica.

## La parte que casi se me pasa: los bloqueos y el reenvío

La regla número uno de la suite es que hay **un solo dueño del firewall**, y es
SecureHIPS. Poner reglas de NAT parece romperla, y no la rompe, por un
mecanismo concreto: **nftables evalúa cada tabla de forma independiente**.
SecureHIPS vive en `inet securehips`, el NAT vive en `inet gateway`, ninguno
borra ni pisa al otro, y cada uno se saca con un solo comando.

Con iptables esto era imposible: había una sola cadena `FORWARD`, todos
escribían ahí, y el último pisaba al anterior. Es la razón de fondo por la que
la suite usa `nft`.

Pero hay algo que sí estaba roto, y era invisible.

**SecureHIPS enganchaba en `input` y en `output` solamente.** En un equipo
normal eso alcanza: todo lo que le importa entra o sale de esa máquina. En un
gateway no, porque el tráfico del celular, del televisor y de la consola **no
entra por `input` ni sale por `output`**: pasa por `forward`.

O sea que el día que convertís el Debian en router, el panel de SecureHIPS
sigue diciendo "12 direcciones bloqueadas" y esas 12 siguen hablando sin
ningún problema con todos los equipos de la casa. Solo el servidor está
cubierto. Un bloqueo que no bloquea es peor que no tener bloqueo, porque además
te hace creer que estás cubierto.

Por eso SecureHIPS ahora crea también una cadena `reenvio` en el hook
`forward`, mirando los mismos sets: una IP bloqueada desde el panel queda
cortada para toda la casa, sin que haya que repetir nada en la tabla del
gateway. En una máquina que no es router esa cadena no ve tráfico y no cuesta
nada, así que se pone siempre y no hay un interruptor que alguien tenga que
acordarse de prender.

El diagnóstico lo verifica en la fila **"Gateway: los bloqueos cubren a la
casa"**. Si SecureHIPS es viejo y no tiene la cadena, sale en rojo con el
motivo.

## Lo que revisa el diagnóstico

Cuando la máquina no reenvía paquetes sale **una sola fila** que lo dice, y no
resta puntaje: la mayoría de las instalaciones no son el router de nadie.
Cuando sí reenvía, salen diez:

- **Gateway: reenvío** — `ip_forward` está en 1.
- **Gateway: NAT** — la tabla `gateway` está cargada. Si no, los paquetes salen
  con la IP privada del celular como origen y no vuelven nunca, porque el mundo
  no sabe rutear a `192.168.50.x`.
- **Gateway: convivencia con SecureHIPS** — las dos tablas están, separadas.
- **Gateway: los bloqueos cubren a la casa** — la cadena de `forward`.
- **Gateway: IPv6** — que el reenvío v6 no esté prendido sin reglas v6. Si lo
  está, los equipos tienen direcciones públicas y salen **sin pasar por el
  NAT**: lo que ves en el panel es la mitad de la historia y la otra mitad va
  por un camino que no estás filtrando.
- **Gateway: equipos conectados** — cuántos pasan por acá (fase 2).
- **Gateway: tráfico reenviado** — los contadores de nftables: ¿está pasando
  algo de verdad por este router, o el equipo navega por el viejo?
- **Gateway: el DNS pasa por Pi-hole** — el fallo silencioso: un equipo que
  navega por acá y consulta el DNS por afuera.
- **Gateway: plan de salida probado** — cuándo fue el último simulacro (fase 3).
- **Gateway: punto único de falla** — siempre en aviso. No es una falla: es un
  dato que hay que tener escrito antes de que pase.

`nft` casi siempre pide root y SecureCenter no corre como root, que está bien.
Cuando no puede leer las reglas lo dice, en vez de afirmar que falta el NAT: un
diagnóstico que manda a arreglar algo que no está roto es peor que uno que no
dice nada.

## Los tres errores que dan síntomas engañosos

**Falta `ct state established,related accept` en la cadena de forward.** Las
respuestas de internet a un pedido del celular caen en el `drop` y no anda
nada. El síntoma engaña porque el ping puede llegar a andar mientras la
navegación no.

**Dos servidores de DHCP.** Anda perfecto un rato y después un equipo agarra la
configuración vieja. Cambia de un arranque a otro, así que "ya lo arreglé"
dura hasta que alguien reinicia el televisor.

**`rp_filter` en estricto con dos salidas a internet.** El filtro de ruta
inversa tira tráfico bueno cuando el ruteo es asimétrico. Con un solo proveedor
no pasa; el día que agregues un segundo, va en `2` y no en `1`.

## Fase 2: probarlo con UN dispositivo

"No con la casa entera" no es una recomendación de estilo. Es lo que hace que,
si algo sale mal, el que se queda sin internet sea un celular y no todos, un
martes a la tarde y no un domingo a la noche.

La forma más simple de que sea un solo equipo es física: la interfaz de la
casa (`eth1`) es un segmento nuevo. Solo lo que enchufes ahí pasa por el
gateway. El resto de la casa sigue colgado del router del proveedor, con su
DHCP prendido, sin enterarse de nada.

Ese es el orden correcto: **el DHCP del router del proveedor se apaga al final
de la fase 2, no al principio.**

### Los cuatro chequeos, en orden

**1. ¿Agarró IP?** El equipo tiene que recibir una del rango, con este
servidor como puerta de enlace. El diagnóstico lo muestra en la fila *"Gateway:
equipos conectados"*, leyendo el archivo de leases del DHCP (no escanea la
red: en la fase donde estás probando si la red anda, un escaneo activo es una
variable más).

**2. ¿Pasa el tráfico POR ACÁ?** Este es el chequeo que separa "el equipo
navega" de "el equipo navega a través de este router". Desde el celular las dos
cosas se ven exactamente igual, y son completamente distintas: en una estás
filtrando, en la otra tenés un router configurado que no usa nadie.

La fila *"Gateway: tráfico reenviado"* lee los contadores de nftables. Si
`reenviados` está en cero mientras el equipo navega, el tráfico está saliendo
por el router viejo.

```bash
sudo nft list counters table inet gateway
```

**3. ¿El DNS pasa por Pi-hole?** Acá está el fallo silencioso de esta fase, y
es el que más vale la pena tener automatizado.

Un celular puede navegar perfecto a través de este router y no pasar **una
sola** consulta por Pi-hole. Alcanza con que tenga un DNS fijo escrito a mano,
o con que el navegador tenga DNS-sobre-HTTPS prendido, que en Chrome y en
Firefox viene activado solo en varios países. Desde el equipo no se ve ninguna
diferencia: la navegación anda, el gateway reenvía, los contadores suben, el
panel se ve lleno de tráfico. Y el filtrado no lo toca.

Lo único que lo delata es que Pi-hole no tiene ni una consulta de esa IP. La
fila *"Gateway: el DNS pasa por Pi-hole"* cruza los equipos del DHCP con la
base de Pi-hole y marca en rojo a los que pasan por el router pero no
consultan.

**4. ¿Los bloqueos lo alcanzan?** Bloqueá una IP a mano desde el panel de
SecureHIPS y comprobá desde el equipo de prueba que efectivamente no llega. Si
llega igual, mirá la fila *"Gateway: los bloqueos cubren a la casa"*: es la
cadena de `forward` que falta.

### Cuándo dejó de ser una prueba

Hay un momento exacto en que esto deja de ser una prueba sin que nadie lo
decida: cuando alguien apaga el DHCP del router viejo, o enchufa el switch
entero al servidor.

Por eso el diagnóstico **cuenta los equipos** en vez de confiar en que te
acordaste. Con uno dice "esto todavía es una prueba"; con doce avisa que si
algo se rompe se queda sin internet la casa entera. No es un error (en algún
momento vas a querer que sea así), pero tiene que ser una decisión y no algo
que pasó.

## Fase 3: el plan de salida, escrito y probado

**Si no lo probaste, no lo tenés.**

El plan está en `gateway/salir-del-gateway.sh`, y tiene cuatro modos:

| Modo | Qué hace |
|---|---|
| `--ver` (por defecto) | muestra qué haría, no toca nada |
| `--salir` | lo hace de verdad |
| `--volver` | vuelve a poner el gateway |
| `--simulacro` | salir, comprobar que la casa anda, y volver |

Correrlo sin argumentos es seguro: alguien lo va a ejecutar para ver qué hace
antes de leerlo, y eso tiene que estar contemplado.

### Por qué el modo `--simulacro` existe

Un plan de salida que nunca corrió es una hoja de papel. Lo que falla al
volver atrás son siempre las mismas cosas, y ninguna se ve leyendo:

- El router del proveedor tiene el DHCP apagado hace seis meses y nadie se
  acuerda de la clave del panel.
- El cable no alcanza porque el servidor se movió de lugar.
- `systemd-networkd` quedó sin `enable` y al reiniciar no levanta.

Todas se descubren la primera vez que lo hacés. La única pregunta es si esa
primera vez es un martes con tiempo o un domingo a la noche con alguien
mirándote.

Corré el simulacro **sentado al lado del servidor**, con teclado y pantalla, no
por SSH: sacar el gateway te puede cortar tu propia sesión y ahí quedás sin
manos. Y tené a mano, en papel o en el celular, cómo se entra al panel del
router del proveedor y dónde va enchufado cada cable.

### El simulacro no se anota solo

El script te pregunta, después de sacar el gateway, si la casa tiene internet.
Si decís que no, **vuelve a poner el gateway igual y no anota nada**, porque un
simulacro que no funcionó no es un plan probado. Eso es exactamente lo que dice
la fase 3.

Si decís que sí, escribe la fecha en `data/ultimo-simulacro-gateway`. La marca
la escribe el script y no el panel, a propósito: tiene que ser prueba de que el
camino de vuelta **corrió**, no de que alguien apretó un botón que dice "ya lo
probé".

El diagnóstico lo mira en la fila *"Gateway: plan de salida probado"*:

- nunca probado → **mal**
- probado hace más de seis meses → **aviso** (en ese plazo cambian las
  interfaces, cambia el módem del proveedor y cambia quién se acuerda)
- probado hace menos → **ok**, con la fecha

### Volver atrás a mano

Si no querés usar el script, son cuatro borrados y un restart:

```bash
sudo nft delete table inet gateway
sudo rm /etc/sysctl.d/99-gateway.conf && sudo sysctl --system
sudo rm /etc/dnsmasq.d/gateway.conf && sudo systemctl restart pihole-FTL
sudo rm /etc/systemd/network/10-lan.network && sudo systemctl restart systemd-networkd
```

Después, a mano: prender el DHCP del router del proveedor, pasar el cable de la
casa del servidor al router, y reconectar cada equipo (van a seguir con la IP
vieja hasta que se les venza el lease, doce horas; no esperes).

La tabla de SecureHIPS **no se toca**: salir del gateway no puede dejarte de
paso sin firewall.
