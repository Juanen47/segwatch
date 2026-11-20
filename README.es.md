# segwatch

**Pruebas continuas de segmentación de red.** Escribe qué red puede hablar
con cuál y por qué puertos. Unas sondas pequeñas dentro de cada red prueban
esos flujos y te avisan cuando la realidad se aparta de la política.

> Estado: borrador (v0.1 en desarrollo). Ya funcionan el modo de un solo
> equipo, las sondas, el controlador, su historial, los avisos, el informe
> HTML y la exportación a Prometheus y Checkmk. [Read in English](README.md).

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

```
  red de invitados       red de servidores        red de gestión
 ┌──────────────┐ deny ┌──────────────────┐ allow ┌──────────────┐
 │    sonda     │─────▶│ sonda + respuesta│◀──────│    sonda     │
 └──────┬───────┘      └────────┬─────────┘  443  └──────┬───────┘
        └──────────── HTTPS (la sonda llama) ────────────┘
                                ▼
               controlador ─▶ informe · avisos · Checkmk / Prometheus
```

* Una **sonda** es un binario estático que se coloca en cada red (un LXC,
  una VM, una Raspberry Pi). Lanza pruebas y responde a las de otras sondas.
* Si un flujo apunta a una **red**, la prueba va contra la sonda de esa red,
  que escucha en todos los puertos de la política. Así un `deny` solo pasa si
  el tráfico de verdad no llega, no porque no hubiera ningún servicio
  escuchando.
* Si apunta a un **target** (un equipo real), segwatch conecta directamente
  con él.

### Resultados

| Resultado | Significado                                                            | `allow` | `deny` |
|-----------|------------------------------------------------------------------------|---------|--------|
| `open`    | Conexión establecida, o eco UDP/ICMP recibido                          | cumple  | falla  |
| `refused` | El equipo real respondió con un reset: el paquete llegó                | falla   | falla  |
| `blocked` | Tiempo agotado, inalcanzable, o reset delante de una sonda que escucha | falla   | cumple |
| `unknown` | UDP a un equipo real sin respuesta: no se puede saber                  | falla   | falla  |
| `unverified` | Parecía bloqueado, pero la sonda de destino está caída (solo con controlador) | – | falla |

Un destino caído no se distingue de un firewall que descarta el tráfico, así
que el controlador solo se fía de un `deny` hacia una sonda mientras esa sonda
siga en contacto con él. Si la sonda de destino lleva más de `--stale` sin
dar señales (3 intervalos por defecto), un `deny` que parecía cumplirse se
guarda como `unverified` y cuenta como fallo. Una sonda cuyo respondedor no
puede escuchar se cierra en vez de seguir consultando, así que un respondedor
roto se detecta igual.
Los resultados hacia una sonda que se conectó por primera vez hace menos de
5 segundos se descartan, para que el orden de arranque de las sondas no dé
falsas alarmas.

## Política

```yaml
version: 1
defaults: { interval: 1h, timeout: 2s }

networks:
  guests:  { cidr: 10.0.30.0/24, probe: { name: probe-guests,  address: 10.0.30.5 } }
  servers: { cidr: 10.0.10.0/24, probe: { name: probe-servers, address: 10.0.10.5 } }

targets:
  nas: { address: 10.0.10.20, network: servers }

flows:
  - name: guests-isolated-from-servers
    from: guests
    to: servers
    ports: [22/tcp, 445/tcp, 53/udp, icmp]
    expect: deny
```

Hay un ejemplo completo en [examples/policy.yaml](examples/policy.yaml). Las
claves desconocidas se rechazan, así que una errata no puede desactivar una
prueba sin que te enteres.

## Uso

```sh
# revisa el fichero de política
segwatch validate -p policy.yaml

# en la sonda de "servers": responde a las pruebas en los puertos de la política
segwatch respond -p policy.yaml --network servers

# en la sonda de "guests": lanza todos los flujos que salen de esa red
segwatch run -p policy.yaml --from guests          # tabla, sale con 1 si algo FALLA
segwatch run -p policy.yaml --from guests --json   # para scripts y CI
```

```
STATUS  FLOW                          TO                    PORT     EXPECT  OBSERVED  DETAIL
PASS    guests-isolated-from-servers  servers (10.0.10.5)   22/tcp   deny    blocked   timeout
FAIL    guests-isolated-from-servers  servers (10.0.10.5)   445/tcp  deny    open
```

### Controlador y sondas

Arranca el controlador una vez, en un sitio al que lleguen todas las sondas
(un solo puerto TCP):

```sh
# en el equipo del controlador
segwatch token add -p policy.yaml --data /var/lib/segwatch probe-guests > guests.token
segwatch token add -p policy.yaml --data /var/lib/segwatch probe-servers > servers.token
segwatch controller -p policy.yaml --data /var/lib/segwatch --listen :8443
# muestra: controller fingerprint: sha256:...
```

Copia cada token a su sonda (`chmod 600`) y arranca la sonda. Solo necesita
la dirección del controlador, la huella y su token: el controlador le dice
qué probar y en qué puertos responder.

```sh
segwatch probe --controller https://10.0.99.10:8443 \
  --fingerprint sha256:... --token-file /etc/segwatch/token --source 10.0.30.5
```

```sh
segwatch status --data /var/lib/segwatch   # sale con 1 si alguna prueba falla o está desfasada
```

* Las sondas siempre llaman al controlador; el controlador nunca se conecta
  a ellas.
* TLS 1.3 con el certificado del controlador fijado por huella: sin CA y sin
  DNS.
* Los tokens se guardan como hash. Cada sonda recibe solo las pruebas de su
  red, y lo que envíe sobre cualquier otra cosa se descarta.
* El historial se guarda en SQLite y se registran los cambios de estado (de
  cumple a falla y al revés).

### Informe

```sh
segwatch report -p policy.yaml --data /var/lib/segwatch -o informe.html   # --days 30 por defecto
```

Una sola página HTML autónoma, sin scripts ni recursos externos, para
archivarla o adjuntarla a una auditoría:

* una matriz de redes de origen frente a destinos, con una etiqueta por
  prueba (✓ cumple la política, ✗ no cumple, ? desfasada, … sin ejecutar);
* cada prueba con el resultado esperado y el observado, desde cuándo, y el
  porcentaje de ejecuciones que cumplieron en el periodo;
* los cambios recientes (se rompe / se recupera);
* el hash SHA-256 de la política, para que el informe diga exactamente qué
  política comprobó.

Sale con 1 si alguna prueba falla o está desfasada, así un cron puede
mandarlo solo cuando algo va mal. Lee el historial y no necesita que el
controlador esté en marcha.

### Monitorización: Prometheus y Checkmk

**Prometheus.** Arranca el controlador con `--metrics 127.0.0.1:9469` y
recoge `/metrics` (HTTP sin cifrar, así que déjalo en localhost o en la red
de gestión). Sin servidor de métricas, `segwatch metrics --data <dir>`
imprime lo mismo para el textfile collector de node_exporter:

```sh
segwatch metrics --data /var/lib/segwatch > /var/lib/node_exporter/segwatch.prom.tmp \
  && mv /var/lib/node_exporter/segwatch.prom.tmp /var/lib/node_exporter/segwatch.prom
```

Totales: `segwatch_checks`, `segwatch_checks_failing` y
`segwatch_checks_stale`. Por prueba, con etiquetas flow, from, to, port,
expect, observed y probe: `segwatch_check_pass`, `segwatch_check_stale`,
`segwatch_check_last_seen_timestamp_seconds` y
`segwatch_check_since_timestamp_seconds`. Una regla de alerta para empezar:
`segwatch_checks_failing > 0 or segwatch_checks_stale > 0`.

**Checkmk.** En el equipo del controlador, añade un check local que
muestra un servicio por flujo más `segwatch summary` (CRIT si una prueba
falla, WARN si está desfasada, con métricas para las gráficas):

```sh
cat > /usr/lib/check_mk_agent/local/segwatch <<'SH'
#!/bin/sh
exec /usr/local/bin/segwatch checkmk --data /var/lib/segwatch
SH
chmod +x /usr/lib/check_mk_agent/local/segwatch
```

### Avisos

El controlador envía avisos a los canales que pongas en `alerts:` dentro de
la política:

| Tipo           | Qué recibe                                                                   |
|----------------|------------------------------------------------------------------------------|
| `ntfy`         | Un mensaje corto por cada tanda de cambios: falla (prioridad alta), se recupera, sonda callada, vuelve a informar |
| `webhook`      | Los mismos eventos en JSON: `{"source":"segwatch","events":[{check_id, flow, from, to, port, expect, outcome, pass, previous_outcome, kind, at}]}` |
| `healthchecks` | Un latido en cada intervalo (como mucho cada 5 min): éxito si todo cumple y nada está desfasado, `/fail` con la lista de fallos si no. Si el controlador se cae, dejan de llegar latidos y avisa Healthchecks |

```yaml
alerts:
  - type: ntfy
    url: https://ntfy.sh/un-tema-largo-y-secreto
    token_file: /etc/segwatch/ntfy.token   # token bearer opcional, también para webhook
  - type: healthchecks
    url: https://hc-ping.com/tu-uuid
```

Una prueba se da por desfasada (su sonda se ha callado) tras 3 intervalos
sin resultado; se cambia con `segwatch controller --stale`. Para mandar un
aviso de prueba a todos los canales: `segwatch alert test -p policy.yaml`.
Las URL de los avisos nunca se escriben en el log, porque los temas de ntfy
y los UUID de Healthchecks valen como contraseñas.

Permisos: no necesita root. El respondedor necesita `CAP_NET_BIND_SERVICE`
para puertos por debajo de 1024, y el ping usa sockets ICMP sin privilegios
(`net.ipv4.ping_group_range`) o, si no, `CAP_NET_RAW`.

## Pruébalo con Docker

[examples/lab](examples/lab) monta tres redes Docker aisladas (gestión,
servidores, invitados), un controlador, tres sondas y un servidor web real.
Necesita Go y Docker, sin root.

```sh
cd examples/lab
./lab.sh up       # compila, crea los tokens y arranca todo
./lab.sh status   # 12 pruebas, 0 fallan
./lab.sh drift    # simula un error en el cortafuegos: invitados llega a servidores
./lab.sh status   # las 5 pruebas de invitados a servidores FALLAN
./lab.sh heal     # lo deshace; vuelve a 0 fallos
./lab.sh outage   # para la sonda de servidores: a los ~40 s sus deny salen "unverified"
./lab.sh restore  # la vuelve a arrancar; vuelve a 0 fallos
./lab.sh alerts   # lo que han recibido ntfy, el webhook y Healthchecks
./lab.sh report   # genera examples/lab/report.html
./lab.sh metrics  # métricas de Prometheus del controlador
./lab.sh checkmk  # salida del check local de Checkmk
./lab.sh down
```

`IPV6=1 ./lab.sh up` (con el mismo prefijo en cada comando) monta el
laboratorio en doble pila, con 24 pruebas: cada una por IPv4 y por IPv6.
Necesita IPv6 en el equipo de Docker, que Docker Desktop y WSL2 tienen.

## IPv6 y redes doble pila

En una red doble pila, IPv6 suele recibir menos atención en el cortafuegos
que IPv4: la VLAN está aislada por IPv4 y por IPv6 pasa todo. segwatch prueba
las dos. Pon a la red `cidr6` y a su sonda `address6` (y a un target
`address6`), y cada flujo hacia ella se prueba una vez por familia:

```yaml
networks:
  guests:  { cidr: 10.0.30.0/24, cidr6: "fd00:30::/64",
             probe: { name: probe-guests, address: 10.0.30.5, address6: "fd00:30::5" } }
targets:
  nas: { address: 10.0.10.20, address6: "fd00:10::20", network: servers }
```

Las pruebas IPv6 tienen un ID que acaba en `@ipv6`. Salen como `22/tcp v6` en
el informe, con `family="ipv6"` en Prometheus y con «(IPv6)» en Checkmk. Una
red también puede ser solo IPv6 (`cidr6` y `address6` sin más). En una sonda
con varias interfaces, fija el origen por familia:
`--source 10.0.30.5,fd00:30::5`.

## Instalar

Descarga la versión de tu plataforma en
[Releases](https://github.com/Juanen47/segwatch/releases): Linux amd64, arm64
y armv7 (Raspberry Pi), y FreeBSD amd64 (OPNsense, pfSense). Cada una es un
único binario estático. Comprueba la descarga antes de ejecutarla:

```sh
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify segwatch_*_linux_amd64.tar.gz --repo Juanen47/segwatch   # compilado por la CI del repo
```

## Compilar

```sh
CGO_ENABLED=0 go build -trimpath -o segwatch ./cmd/segwatch
go test ./...
```

## Hoja de ruta

- [x] Fichero de política con validación
- [x] Pruebas TCP, UDP e ICMP con clasificación del resultado
- [x] Respondedor y modo `run` de un solo equipo
- [x] Controlador: las sondas se autentican con un token sobre TLS fijado y piden sus pruebas
- [x] Planificación en la sonda, historial en SQLite y detección de cambios de estado
- [x] Avisos: webhook, ntfy, Healthchecks
- [x] Informe HTML con la matriz esperado frente a observado
- [x] Check local de Checkmk y métricas de Prometheus
- [x] Flujos IPv6 y redes doble pila
- [x] Binarios publicados con sumas de comprobación y procedencia de la compilación

## Uso responsable

Úsalo solo en redes propias o en las que tengas autorización por escrito.
segwatch solo contacta lo que lista la política, con un límite de velocidad.
Consulta [SECURITY.es.md](SECURITY.es.md).

## Licencia

[Apache 2.0](LICENSE)
