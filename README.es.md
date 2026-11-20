# segwatch

**Pruebas continuas de segmentación de red.** Escribe qué red puede hablar
con cuál y por qué puertos. Unas sondas pequeñas dentro de cada red prueban
esos flujos y te avisan cuando la realidad se aparta de la política.

> Estado: borrador (v0.1 en desarrollo). Ya funcionan el modo `run` en un
> solo equipo y el respondedor; el controlador, el historial y los avisos
> vienen después. [Read in English](README.md).

## Por qué

Las VLAN y las reglas del cortafuegos se configuran una vez, y un día un
cambio deja que la wifi de invitados llegue a los servidores sin que nadie
se entere hasta la auditoría del año siguiente. PCI DSS pide probar la
segmentación al menos cada 12 meses y tras cada cambio (cada 6 meses para
proveedores de servicios), y casi todo el mundo lo hace a mano con nmap y
una hoja de cálculo.

Lo que existe es manual (matrices de ping con interfaz gráfica), scripts de
auditoría de un solo uso, solo para Kubernetes (NetAssert) o suites completas
de ataque simulado. segwatch es una comprobación pequeña, declarativa y
permanente que se integra con tu monitorización.

## Cómo funciona

* Una **sonda** es un binario estático que se coloca en cada red (un LXC,
  una VM, una Raspberry Pi). Lanza pruebas y responde a las de otras sondas.
* Si un flujo apunta a una **red**, la prueba va contra la sonda de esa red,
  que escucha en todos los puertos de la política. Así un `deny` solo pasa si
  el tráfico de verdad no llega, no porque no hubiera ningún servicio.
* Si apunta a un **target** (un equipo real), segwatch conecta directamente.

### Resultados

| Resultado | Significado                                                          | `allow` | `deny` |
|-----------|----------------------------------------------------------------------|---------|--------|
| `open`    | Conexión establecida, o eco UDP/ICMP recibido                        | cumple  | falla  |
| `refused` | El equipo real respondió con un reset: el paquete llegó              | falla   | falla  |
| `blocked` | Tiempo agotado, inalcanzable, o reset delante de una sonda que escucha | falla | cumple |
| `unknown` | UDP a un equipo real sin respuesta: no se puede saber                | falla   | falla  |

## Uso

```sh
segwatch validate -p policy.yaml                     # revisa la política
segwatch respond  -p policy.yaml --network servers   # en la sonda de "servers"
segwatch run      -p policy.yaml --from guests       # en la sonda de "guests"
```

`run` devuelve 1 si algún flujo no cumple, para usarlo en scripts y CI. La
política de ejemplo está en [examples/policy.yaml](examples/policy.yaml).

No necesita root: el respondedor necesita `CAP_NET_BIND_SERVICE` para
puertos por debajo de 1024, y el ping usa sockets ICMP sin privilegios
(`net.ipv4.ping_group_range`) o `CAP_NET_RAW`.

## Uso responsable

Úsalo solo en redes propias o con autorización por escrito. segwatch solo
contacta lo que lista la política, con un límite de velocidad.

## Licencia

[Apache 2.0](LICENSE)
