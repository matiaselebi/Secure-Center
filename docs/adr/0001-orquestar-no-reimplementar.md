# ADR 0001: Orquestar los tres proyectos, no reimplementarlos

## Estado

Aceptada.

## Contexto

SecureCenter une SecureProxy + SecureDNS + SecureVPN en un centro de control.
Había dos caminos: (a) mover/duplicar la lógica de los tres adentro de
SecureCenter, o (b) dejar a cada proyecto como la fuente de verdad de sí
mismo y que SecureCenter solo los coordine.

## Decisión

SecureCenter **orquesta**: cada acción (encender núcleo, apagar todo,
encender VPN) es una secuencia de pasos que ejecutan los **propios scripts
de cada proyecto** (`run_proxy.py`, `run_dns.py`, `connect_vpn.py`, etc.)
usando el Python del venv de ese proyecto. No copia ni reimplementa nada.

Los proyectos se ubican por **autodetección**: SecureCenter busca entre las
carpetas hermanas la que tiene el paquete característico (`src/secureproxy`,
`src/securedns`, `src/securevpn`), sin depender del nombre de la carpeta. Se
puede fijar la ruta a mano en `config/config.yaml`.

## Consecuencias

- Cada proyecto sigue siendo usable y testeable por separado; SecureCenter
  no los acopla.
- Si un proyecto cambia por dentro, SecureCenter no se entera mientras
  mantenga sus scripts de entrada (contrato mínimo: run/stop, connect/
  disconnect, lab_up/provision).
- SecureCenter puede evolucionar sin tocar los otros tres.
- Las operaciones se construyen como "planes" de pasos inspeccionables en
  dry-run, lo que las hace testeables sin ejecutar procesos reales.
