#!/usr/bin/env bash
set -euo pipefail

# Live-test protocol for falcosidekick v3 against the maintainer's kind cluster.
# See ai/core/live-test-protocol.md for the contract.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${V3_IMAGE:-ghcr.io/c2ndev/falcosidekick}:${V3_TAG:-v3-local}"
NAMESPACE="${V3_NAMESPACE:-falco}"
LOCAL_PORT="${V3_LOCAL_PORT:-28010}"
TIMEOUT_READY="${V3_TIMEOUT_READY:-90s}"
FALCO_PROPAGATION_WAIT="${V3_FALCO_WAIT:-30}"
WEBHOOK_WAIT="${V3_WEBHOOK_WAIT:-8}"

# Auto-detect the kind cluster name when only one exists; override with V3_KIND_CLUSTER.
if [[ -z "${V3_KIND_CLUSTER:-}" ]]; then
  _kind_clusters=$(kind get clusters 2>/dev/null || true)
  if [[ $(echo "$_kind_clusters" | grep -c .) -eq 1 ]]; then
    V3_KIND_CLUSTER="$(echo "$_kind_clusters" | head -1)"
  fi
fi
KIND_CLUSTER="${V3_KIND_CLUSTER:-kind}"
FAIL=0
PF_PID=""

log()  { printf '[live-test] %s\n' "$*"; }
fail() { printf '[live-test][FAIL] %s\n' "$*" >&2; FAIL=$((FAIL+1)); }

cleanup() {
  if [[ -n "$PF_PID" ]] && kill -0 "$PF_PID" 2>/dev/null; then
    kill "$PF_PID" 2>/dev/null || true
    wait "$PF_PID" 2>/dev/null || true
  fi
  log "teardown: deleting Component + webhook-receiver"
  kubectl delete --ignore-not-found -f "$HERE/component.yaml" >/dev/null 2>&1 || true
  kubectl delete --ignore-not-found -f "$HERE/webhook-receiver.yaml" >/dev/null 2>&1 || true
}
trap cleanup EXIT

require() { command -v "$1" >/dev/null 2>&1 || { fail "missing required binary: $1"; exit 1; }; }
require kubectl
require kind
require docker

log "1/9 cluster reachable?"
kubectl cluster-info >/dev/null || { fail "no cluster reachable (kubectl cluster-info)"; exit 1; }

log "2/9 loading image $IMAGE into kind cluster '$KIND_CLUSTER'"
kind load docker-image --name "$KIND_CLUSTER" "$IMAGE" >/dev/null \
  || { fail "kind load docker-image failed (cluster: $KIND_CLUSTER). Build it first via 'make build-image-v3-local'"; exit 1; }

log "3/9 applying webhook-receiver + Component CR"
kubectl apply -f "$HERE/webhook-receiver.yaml" >/dev/null
kubectl apply -f "$HERE/component.yaml" >/dev/null

log "4/9 waiting for webhook-receiver + falcosidekick to be Ready (timeout $TIMEOUT_READY)"
kubectl -n "$NAMESPACE" rollout status deployment/webhook-receiver --timeout="$TIMEOUT_READY" \
  || { fail "webhook-receiver did not become Ready"; exit 1; }

# The falco-operator reconciles the Component CR into a Deployment asynchronously,
# so the pod may not exist immediately. Poll for its existence, then wait for Ready.
sidekick_deadline=$(( $(date +%s) + ${TIMEOUT_READY%s} ))
while true; do
  if kubectl -n "$NAMESPACE" get pod -l app.kubernetes.io/name=falcosidekick 2>/dev/null | grep -q falcosidekick; then
    break
  fi
  if [[ $(date +%s) -gt $sidekick_deadline ]]; then
    fail "falcosidekick pod never appeared within ${TIMEOUT_READY} (operator did not reconcile Component CR)"
    exit 1
  fi
  sleep 2
done
kubectl -n "$NAMESPACE" wait --for=condition=Ready pod -l app.kubernetes.io/name=falcosidekick --timeout="$TIMEOUT_READY" \
  || { fail "falcosidekick pod did not become Ready"; exit 1; }
log "  ok: pod Ready [criterion 1]"

log "5/9 starting port-forward to falcosidekick:2801 -> localhost:$LOCAL_PORT"
kubectl -n "$NAMESPACE" port-forward svc/falcosidekick "$LOCAL_PORT:2801" >/dev/null 2>&1 &
PF_PID=$!
sleep 2

curl_ok() { curl -fsS --max-time 5 "$@" 2>&1; }

extract_input_total() {
  local body="$1"
  local total=0
  while read -r n; do
    total=$((total + n))
  done < <(echo "$body" | grep -E '^falcosidekick_input_total\{' | awk '{print $NF}' | awk -F'.' '{print $1}')
  echo "$total"
}

# webhook_sent_total reads sent_total for the "webhook" output from /api/v1/pipeline/status.
webhook_sent_total() {
  curl_ok "http://127.0.0.1:$LOCAL_PORT/api/v1/pipeline/status" 2>/dev/null \
    | python3 -c 'import json,sys
try:
  for o in json.load(sys.stdin).get("outputs", []):
    if o.get("name") == "webhook":
      print(o.get("sent_total", 0)); break
  else:
    print(0)
except Exception:
  print(0)'
}

log "6/9 HTTP smoke checks"
if body=$(curl_ok "http://127.0.0.1:$LOCAL_PORT/healthz") && [[ "$body" == *'"status":"ok"'* ]]; then
  log "  ok: /healthz [criterion 2]"
else
  fail "/healthz did not return {status:ok}: $body"
fi

if body=$(curl_ok "http://127.0.0.1:$LOCAL_PORT/version") && [[ "$body" == *'"version"'* ]]; then
  log "  ok: /version [criterion 3]"
else
  fail "/version unexpected: $body"
fi

if body=$(curl_ok "http://127.0.0.1:$LOCAL_PORT/api/v1/config") && [[ "$body" == *'listen_port'* ]]; then
  log "  ok: /api/v1/config [criterion 4]"
else
  fail "/api/v1/config unexpected: $body"
fi

# Baseline metric counter before any events.
metrics_before=$(curl_ok "http://127.0.0.1:$LOCAL_PORT/metrics" || echo "")
baseline_total=$(extract_input_total "$metrics_before")
log "  baseline falcosidekick_input_total = $baseline_total"

webhook_baseline=$(webhook_sent_total)
log "  baseline webhook sent_total = $webhook_baseline"

log "7/9 synthetic POST / event"
payload='{"time":"2026-04-22T00:00:00Z","rule":"live-test synthetic","output":"live-test synthetic output","source":"syscall","priority":"Warning","hostname":"live-test","tags":["live-test"],"output_fields":{"proc.name":"synthetic"}}'
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -X POST -H "Content-Type: application/json" -d "$payload" \
  "http://127.0.0.1:$LOCAL_PORT/")
if [[ "$status" == "200" ]]; then
  log "  ok: POST / -> 200 [criterion 5a]"
else
  fail "POST / returned HTTP $status"
fi

log "  polling webhook output for up to ${WEBHOOK_WAIT}s"
synthetic_delivered=0
for _ in $(seq 1 "$WEBHOOK_WAIT"); do
  wh_now=$(webhook_sent_total)
  if [[ "$wh_now" -gt "$webhook_baseline" ]]; then
    synthetic_delivered=1
    break
  fi
  sleep 1
done
if [[ "$synthetic_delivered" -eq 1 ]]; then
  log "  ok: falcosidekick forwarded event to webhook output (sent_total ${webhook_baseline} -> $(webhook_sent_total)) [criterion 5b]"
else
  fail "webhook output sent_total did not advance within ${WEBHOOK_WAIT}s (baseline=$webhook_baseline)"
  log "  diagnostic: pipeline status:"
  curl_ok "http://127.0.0.1:$LOCAL_PORT/api/v1/pipeline/status" 2>&1 | sed 's/^/    /' >&2 || true
fi

log "8/9 real Falco rule trigger (read /etc/shadow in a pod)"
# Capture baseline BEFORE launching the trigger. `kubectl run --rm` blocks ~13s
# waiting for the pod to exit + be garbage-collected; Falco's event fires and
# reaches falcosidekick during that window. If we capture the baseline after
# the run, we miss the very delivery we're trying to detect.
post_trigger_webhook=$(webhook_sent_total)
log "  webhook sent_total baseline before trigger = $post_trigger_webhook"
kubectl run -n default --rm -i --restart=Never --image=alpine:3.22 "live-test-trigger-$$" -- \
    sh -c 'cat /etc/shadow >/dev/null 2>&1 || true' >/dev/null 2>&1 \
  || { fail "kubectl run live-test-trigger failed"; }
log "  triggered; polling for up to ${FALCO_PROPAGATION_WAIT}s"
counter_advanced=0
falco_forwarded=0
after_total=0
for _ in $(seq 1 "$FALCO_PROPAGATION_WAIT"); do
  metrics_after=$(curl_ok "http://127.0.0.1:$LOCAL_PORT/metrics" 2>/dev/null || echo "")
  after_total=$(extract_input_total "$metrics_after")
  if [[ "$after_total" -gt "$baseline_total" ]]; then
    counter_advanced=1
  fi
  wh_now=$(webhook_sent_total)
  if [[ "$wh_now" -gt "$post_trigger_webhook" ]]; then
    falco_forwarded=1
  fi
  if [[ "$counter_advanced" -eq 1 && "$falco_forwarded" -eq 1 ]]; then
    break
  fi
  sleep 1
done

log "  falcosidekick_input_total: before=$baseline_total after=$after_total"
if [[ "$counter_advanced" -eq 1 ]]; then
  log "  ok: /metrics input counter advanced [criterion 7]"
else
  fail "/metrics input counter did not advance (baseline=$baseline_total, after=$after_total)."
fi

if [[ "$falco_forwarded" -eq 1 ]]; then
  log "  ok: Falco event forwarded through falcosidekick's webhook output (sent_total ${post_trigger_webhook} -> $(webhook_sent_total)) [criterion 6]"
else
  fail "webhook sent_total did not advance after Falco trigger within ${FALCO_PROPAGATION_WAIT}s (baseline=$post_trigger_webhook)"
  log "  diagnostic: pipeline status:"
  curl_ok "http://127.0.0.1:$LOCAL_PORT/api/v1/pipeline/status" 2>&1 | sed 's/^/    /' >&2 || true
fi

log "9/10 UI shell (browser-shape request)"
if decoded=$(curl -sS --compressed -H "Accept-Encoding: gzip" "http://127.0.0.1:$LOCAL_PORT/") && [[ "$decoded" == *'<html'* ]]; then
  log "  ok: GET / with Accept-Encoding returned UI HTML shell [criterion 8]"
else
  fail "GET / with Accept-Encoding did not return decoded HTML (variant may be slim; set V3_TAG=v3-local-slim to skip this criterion)"
fi

log "10/10 UI-driven output PUT (updates provisioned webhook under allow_ui_updates=true; next file reload would restore the file version)"
UI_WRITE_WAIT="${V3_UI_WRITE_WAIT:-10}"
pre_ui_sent="$(webhook_sent_total)"
put_resp=$(curl -sS -w '\n%{http_code}' -X PUT \
  -H "Content-Type: application/json" \
  -d '{"config":{"method":"POST"}}' \
  "http://127.0.0.1:$LOCAL_PORT/api/v1/pipeline/outputs/webhook" || true)
status=$(echo "$put_resp" | tail -n1)
if [[ "$status" == "200" ]]; then
  log "  ok: PUT /api/v1/pipeline/outputs/webhook -> 200 [criterion 9a]"
  start_ts=$(date +%s)
  while :; do
    sleep 1
    curl -sS -X POST -H 'Content-Type: application/json' \
      -d "$(printf '{"time":"%s","output":"ui-apply-probe","priority":"Error","rule":"ui-apply","source":"test"}' "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)")" \
      "http://127.0.0.1:$LOCAL_PORT/" >/dev/null 2>&1 || true
    new_sent="$(webhook_sent_total)"
    if [[ "$new_sent" -gt "$pre_ui_sent" ]]; then
      log "  ok: UI-updated webhook output delivered events (sent_total ${pre_ui_sent} -> ${new_sent}) [criterion 9b]"
      break
    fi
    if (( $(date +%s) - start_ts >= UI_WRITE_WAIT )); then
      fail "UI-updated webhook output did not deliver any event within ${UI_WRITE_WAIT}s (baseline=${pre_ui_sent})"
      break
    fi
  done
else
  fail "PUT /api/v1/pipeline/outputs/webhook returned '$status' (expected 200)"
fi

if [[ "$FAIL" -gt 0 ]]; then
  printf '[live-test] FAILED with %d criteria unmet\n' "$FAIL" >&2
  exit 1
fi
log "live-test PASSED"
