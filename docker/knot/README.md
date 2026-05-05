# Knot + dnstap Docker Compose stack

This compose project runs:

- Knot DNS (`knot`) exposing DNS on host `DNS_PORT`
- RFC9567 agent (`agent`) in `dnstap` mode, listening on a shared unix socket
- Prometheus and Grafana using the same config and dashboards from `docker/common/`

## Start

```bash
cp docker/knot/.env.example docker/knot/.env
docker compose \
  --env-file docker/knot/.env \
  -f docker/knot/docker-compose.yml \
  up --build -d
```

## Notes

- Prometheus config is reused from `docker/common/prometheus/prometheus.yml`.
- Grafana provisioning and dashboard JSON are reused from `docker/common/grafana/`.
- The Knot zone currently serves `agent.example.` from `docker/knot/knot/zones/agent.example.zone`.
