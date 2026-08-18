# Suricata para esta suite: instalar, dejarlo mirando, y no guardar de más

Suricata es **opcional**. La suite funciona entera sin él, con menos
visibilidad de red. Este documento es para el caso en que lo quieras poner, y
está escrito en el orden en que conviene decidir: primero si tu equipo da,
después que quede mirando y no cortando, y al final que no guarde el contenido
de tu tráfico.

## 1. Antes de instalarlo: ¿el equipo da?

Suricata con el ruleset abierto de Emerging Threats (unas 40.000 reglas) se
come más de un giga de RAM solo con el árbol de reglas cargado, y arriba de
eso están las tablas de flujos, que crecen con el tráfico.

En el equipo equivocado no anda lento. Se queda sin memoria, el kernel elige a
quién matar, y elige al proceso más gordo, que en un gateway casero puede ser
Pi-hole. O sea: instalás un IDS y te quedás sin DNS.

El diagnóstico de SecureCenter tiene una fila **"Suricata: hardware"** que
compara lo que tiene *esta* máquina contra el piso conocido:

| Lo que tiene | Qué dice |
|---|---|
| menos de 2 GB de RAM | **mal**: no lo instales acá |
| menos de 4 GB, o un solo núcleo | **aviso**: entra justo, va a descartar paquetes si el tráfico sube |
| 4 GB o más y 2 núcleos o más | **ok** |

Ese número es un piso, no una promesa. El que manda es el que sale de medir
con tu tráfico real, y la forma de medirlo es mirar el contador
`capture.kernel_drops` en `/var/log/suricata/stats.log`: si sube, Suricata está
tirando paquetes y lo que ves en el panel es una parte de lo que pasó.

## 2. Instalar

En Debian y derivados (incluido Raspberry Pi OS):

```bash
sudo apt install suricata
sudo suricata-update            # baja el ruleset de Emerging Threats
```

Decile qué interfaz mirar y con qué red se corresponde tu casa, en
`/etc/suricata/suricata.yaml`:

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.1.0/24]"     # tu red, la de verdad
    EXTERNAL_NET: "!$HOME_NET"

af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```

`HOME_NET` bien puesto es lo que hace que las reglas distingan "algo de afuera
atacando adentro" de "algo de adentro hablando con afuera". Con el valor por
defecto (que suele ser todas las redes privadas) las dos cosas se mezclan y la
mitad de las alertas dejan de significar lo que dicen.

## 3. Que quede mirando, no cortando

`af-packet` es una copia del tráfico: Suricata mira y no está en el camino.
Eso es lo que se quiere.

Lo que **no** va es NFQUEUE (`-q 0`) ni `copy-mode: ips`. Ahí los paquetes
pasan *por* Suricata, y una regla del ruleset abierto puede cortarte internet
en tu propia casa. El que la escribió no te conoce ni sabe qué usás, y el
falso positivo dejó de ser un renglón en una pantalla: es el Netflix que no
abre un domingo.

El que bloquea en esta suite es SecureHIPS, que tiene vencimiento, escalera de
duraciones, lista blanca, motivo registrado y un botón para levantar el
bloqueo. Una regla de red cortando sola no tiene nada de eso.

SecureCenter lo verifica solo, en la fila **"Suricata: modo"**, y lo hace
mirando la línea de comando del proceso que está corriendo (leída de `/proc`),
no el archivo de configuración. El `suricata.yaml` que trae el paquete viene
con la sección de NFQUEUE escrita y comentada como ejemplo: buscar esas
palabras en el texto diría "modo IPS" en una instalación recién hecha que no lo
está.

Lo que está corriendo es un hecho. Lo que dice un archivo de configuración es
una intención, y encima puede estar comentada.

## 4. Que no guarde el contenido de tu tráfico

Copiá la sección `outputs` de [`suricata-eve-log.yaml`](suricata-eve-log.yaml)
sobre la de tu `/etc/suricata/suricata.yaml`.

Lo que apaga, y por qué cada una:

- `payload`, `payload-printable`, `packet`: el contenido del paquete, en base64
  y en texto. Adentro va la contraseña que alguien escribió en un formulario
  sin HTTPS.
- `http-body`, `http-body-printable`: el cuerpo de los pedidos HTTP. Un
  formulario entero.
- `tagged-packets`: todos los paquetes de un flujo marcado.
- `pcap-log`: la captura cruda. Todo lo que pasa por la red de tu casa, tal
  cual pasó, en un archivo.
- `file-store`: los archivos que ve pasar, guardados enteros. Un adjunto de
  mail, un PDF que alguien bajó.

Lo único que se deja prendido de esa familia es `metadata: yes`, que trae de
qué familia de malware es la firma. Sin eso queda el número de regla pelado.

**Por qué no alcanza con que SecureCenter lo filtre al leer.** Los campos que
SecureCenter copia de una alerta son una lista blanca escrita en el código, y
hay un test que arma una alerta con una contraseña adentro y verifica que esa
cadena no aparezca en ningún lado del evento. Pero mientras la opción esté
prendida del lado de Suricata, el dato **igual se escribe** en `eve.json`, que
queda en el disco del gateway, entra en los backups y lo lee cualquiera que
tenga una shell ahí. Filtrarlo al leerlo no lo borra del disco.

Son dos mitades del mismo problema y hacen falta las dos. SecureCenter revisa
la mitad que no controla y la reporta en el diagnóstico (filas "Suricata:
contenido en eve.json", "Suricata: pcap-log" y "Suricata: file-store"), con el
cambio exacto en la columna del arreglo. No la corrige solo: `suricata.yaml` no
es su archivo y tocarlo necesita root.

Después de editar:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml    # valida sin arrancar
sudo systemctl restart suricata
```

## 5. Conectarlo a SecureCenter

```yaml
# config/config.yaml de SecureCenter
externos:
  suricata_eve: "/var/log/suricata/eve.json"
  suricata_yaml: "/etc/suricata/suricata.yaml"
```

`eve.json` suele ser de root, y SecureCenter no corre como root, que está
bien. Para que lo pueda leer:

```bash
sudo usermod -aG adm $USER      # y volvé a iniciar sesión
```

Se lee solo la **cola** del archivo, los últimos 2 MB. En un gateway con
tráfico real esto pesa cientos de megas y el panel se repinta cada pocos
segundos: leerlo entero cada vez sería colgar la máquina para mostrar una
tabla. No hay marca de agua guardada, a propósito, porque el archivo rota y un
offset guardado después de una rotación apunta a cualquier lado.

La contracara, dicha de frente: una alerta vieja enterrada bajo megas de
tráfico posterior no se ve. Es la misma semántica que tienen todos los otros
adaptadores de Detect ("los últimos N eventos").

## 6. Pedir un bloqueo a partir de una alerta

Es la fase 4 del punto 9, y es un **botón**, no una automatización. Está
explicado en el [ADR 0002](adr/0002-suricata-mira-securehips-aplica.md) y en el
README, en la sección de incidentes.

Lo importante en una línea: de un incidente que involucra una alerta de red,
SecureCenter puede pedirle a SecureHIPS que bloquee la IP **de afuera**, nunca
la de tu propia red. En una alerta de C2 saliente el origen es tu propia PC, y
bloquearla sería dejar sin internet al equipo que quisiste proteger.
