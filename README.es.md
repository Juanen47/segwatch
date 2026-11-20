# segwatch

**Pruebas continuas de segmentación de red.** Escribe qué red puede hablar
con cuál y por qué puertos. Unas sondas pequeñas dentro de cada red prueban
esos flujos y te avisan cuando la realidad se aparta de la política.

> Estado: borrador (v0.1 en desarrollo). Ya funcionan el modo de un solo
> equipo, las sondas, el controlador, su historial, los avisos y el informe
> HTML. [Read in English](README.md).

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
./lab.sh alerts   # lo que han recibido ntfy, el webhook y Healthchecks
./lab.sh report   # genera examples/lab/report.html
./lab.sh down
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
- [ ] Check local de Checkmk y métricas de Prometheus
- [ ] Flujos IPv6 y binarios publicados

## Uso responsable

Úsalo solo en redes propias o en las que tengas autorización por escrito.
segwatch solo contacta lo que lista la política, con un límite de velocidad.
Consulta [SECURITY.es.md](SECURITY.es.md).

## Licencia

[Apache 2.0](LICENSE)
