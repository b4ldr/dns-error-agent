#!/usr/bin/env python3

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

GRAFANA_URL = os.environ.get("GRAFANA_URL", "http://127.0.0.1:3000")
GRAFANA_USER = os.environ.get("GRAFANA_USER", "admin")
GRAFANA_PASSWORD = os.environ.get("GRAFANA_PASSWORD", "admin")
DASHBOARD_UID = os.environ.get("GRAFANA_DASHBOARD_UID", "dns-error-agent-overview")
DATASOURCE_UID = os.environ.get("GRAFANA_DATASOURCE_UID", "prometheus")
TIMEOUT_SECONDS = int(os.environ.get("GRAFANA_VALIDATE_TIMEOUT", "120"))


def auth_header() -> str:
    token = base64.b64encode(
        f"{GRAFANA_USER}:{GRAFANA_PASSWORD}".encode("utf-8")
    ).decode("ascii")
    return f"Basic {token}"


def request_json(url: str, method: str = "GET", body=None):
    headers = {
        "Authorization": auth_header(),
        "Accept": "application/json",
    }
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(url, headers=headers, method=method, data=data)
    with urllib.request.urlopen(req, timeout=10) as response:
        payload = response.read()
        if not payload:
            return None
        return json.loads(payload.decode("utf-8"))


def wait_for(description: str, func):
    deadline = time.time() + TIMEOUT_SECONDS
    last_error = None
    while time.time() < deadline:
        try:
            result = func()
            if result:
                print(f"OK: {description}")
                return result
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        time.sleep(2)
    raise RuntimeError(f"timed out waiting for {description}: {last_error}")


def flatten_panels(panels):
    flat = []
    for panel in panels or []:
        flat.append(panel)
        flat.extend(flatten_panels(panel.get("panels", [])))
    return flat


def collect_query_targets(dashboard):
    queries = []
    for panel in flatten_panels(dashboard.get("panels", [])):
        title = panel.get("title", f"panel-{panel.get('id', 'unknown')}")
        for target in panel.get("targets", []):
            expr = target.get("expr")
            if not expr:
                continue
            queries.append(
                {
                    "panel_title": title,
                    "ref_id": target.get("refId", "A"),
                    "expr": expr,
                    "instant": bool(target.get("instant", False)),
                }
            )
    return queries


def validate_query(query):
    now_ms = int(time.time() * 1000)
    body = {
        "from": str(now_ms - 300000),
        "to": str(now_ms),
        "queries": [
            {
                "refId": query["ref_id"],
                "expr": query["expr"],
                "instant": query["instant"],
                "range": not query["instant"],
                "datasource": {"uid": DATASOURCE_UID, "type": "prometheus"},
                "intervalMs": 1000,
                "maxDataPoints": 43200,
            }
        ],
    }

    response = request_json(f"{GRAFANA_URL}/api/ds/query", method="POST", body=body)
    results = (response or {}).get("results", {})
    result = results.get(query["ref_id"], {})
    if "error" in result:
        raise RuntimeError(
            f"panel '{query['panel_title']}' query failed: {result['error']}"
        )


def main():
    wait_for("Grafana health", lambda: request_json(f"{GRAFANA_URL}/api/health"))
    wait_for(
        "Prometheus datasource",
        lambda: request_json(f"{GRAFANA_URL}/api/datasources/uid/{DATASOURCE_UID}"),
    )
    dashboard_response = wait_for(
        "provisioned dashboard",
        lambda: request_json(f"{GRAFANA_URL}/api/dashboards/uid/{DASHBOARD_UID}"),
    )

    dashboard = dashboard_response.get("dashboard", {})
    queries = collect_query_targets(dashboard)
    if not queries:
        raise RuntimeError("no panel queries found in dashboard")

    print(f"Validating {len(queries)} panel queries")
    for query in queries:
        validate_query(query)
        print(f"OK: {query['panel_title']} [{query['ref_id']}]")

    print("Dashboard validation succeeded")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
