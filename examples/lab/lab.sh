#!/bin/sh
# segwatch lab on Docker: three isolated networks, a controller, three probes
# one real web server and an alert receiver.
# Usage: ./lab.sh up | status | drift | heal | alerts | report | metrics |
#        checkmk | down
# Dual-stack (every check over IPv4 and IPv6): IPV6=1 ./lab.sh <command>
set -eu
cd "$(dirname "$0")"
POLICY=policy.yaml
export FP="${FP:-unset}" # set for real by "up"; keeps compose quiet otherwise
if [ "${IPV6:-0}" = 1 ]; then
  POLICY=policy-ipv6.yaml
  export COMPOSE_FILE=compose.yaml:compose.ipv6.yaml
fi
sw() { docker compose exec -T controller /segwatch "$@"; }

case "${1:-up}" in
up)
  CGO_ENABLED=0 go build -trimpath -o segwatch ../../cmd/segwatch
  mkdir -p data/tokens && chmod 777 data data/tokens
  docker compose build -q
  run() { docker run --rm -u 65534:65534 -v "$PWD:/lab" segwatch-lab "$@"; }
  for p in probe-mgmt probe-servers probe-guests; do
    [ -s "data/tokens/$p" ] || run token add -p /lab/$POLICY --data /lab/data "$p" > "data/tokens/$p"
  done
  chmod 644 data/tokens/*
  FP=$(run fingerprint --data /lab/data | awk '{print $NF}')
  export FP
  echo "controller fingerprint: $FP"
  docker compose up -d
  echo "wait ~20s, then: ./lab.sh status"
  ;;
status) sw status --data /lab/data --stale 1m ;;
drift)
  # simulate a firewall mistake: guests can now reach the servers network
  if [ "${IPV6:-0}" = 1 ]; then
    docker network connect --ip 172.31.20.99 --ip6 fd00:31:20::99 segwatch-lab_servers segwatch-lab-probe-guests-1
  else
    docker network connect --ip 172.31.20.99 segwatch-lab_servers segwatch-lab-probe-guests-1
  fi
  echo "guests probe now has a leg in servers; wait ~20s, then: ./lab.sh status" ;;
heal)
  docker network disconnect segwatch-lab_servers segwatch-lab-probe-guests-1
  echo "fixed; wait ~20s, then: ./lab.sh status" ;;
report)
  sw report -p /lab/$POLICY --data /lab/data -o /lab/data/report.html || true
  cp data/report.html report.html && echo "open examples/lab/report.html" ;;
metrics) docker compose exec -T alerts wget -qO- http://172.31.10.10:9469/metrics ;;
checkmk) sw checkmk --data /lab/data --stale 1m ;;
alerts) docker compose exec -T alerts cat /tmp/alerts.log 2>/dev/null || echo "no alerts yet" ;;
down) docker compose down -v; rm -rf data segwatch report.html ;;
*) echo "usage: $0 up|status|drift|heal|alerts|report|metrics|checkmk|down" >&2; exit 2 ;;
esac
