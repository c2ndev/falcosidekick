#!/usr/bin/env bash
#
# One-shot dev loop: build the v3 UI image, load it into a kind cluster,
# deploy falcosidekick via the falco-operator Component CR (same manifests
# the live-test uses), port-forward the service, and start `bun run dev`
# with FALCOSIDEKICK_BACKEND pointing at the forward.
#
# On exit (Ctrl-C / dev-server quit) the port-forward is stopped. Cluster
# resources stay deployed for fast iteration. Pass --clean to tear them down.
#
# Usage:
#   ./hack/ui-dev-cluster.sh [options]
#
# Options:
#   -n NAMESPACE    target namespace (default: falco)
#   -s SERVICE      target service name (default: falcosidekick)
#   -l PORT         local port for port-forward (default: 2801)
#   -p PORT         service port (default: 2801)
#   -k NAME         kind cluster name (default: auto-detect single cluster)
#   --skip-build    reuse existing :v3-local image; skip build + kind load
#   --skip-deploy   do not apply webhook-receiver/Component CR (reuse deployed)
#   --clean         tear down cluster resources on exit
#   -h, --help      print this help

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

CLEAN_ON_EXIT=0
SKIP_BUILD=0
SKIP_DEPLOY=0
NAMESPACE="falco"
SERVICE="falcosidekick"
LOCAL_PORT="2801"
BACKEND_PORT="2801"
CLUSTER=""
IMAGE="${V3_IMAGE:-ghcr.io/c2ndev/falcosidekick}:${V3_TAG:-v3-local}"

usage() { sed -n '1,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//' | sed '$d'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n) NAMESPACE="$2"; shift 2;;
    -s) SERVICE="$2"; shift 2;;
    -l) LOCAL_PORT="$2"; shift 2;;
    -p) BACKEND_PORT="$2"; shift 2;;
    -k) CLUSTER="$2"; shift 2;;
    --skip-build) SKIP_BUILD=1; shift;;
    --skip-deploy) SKIP_DEPLOY=1; shift;;
    --clean) CLEAN_ON_EXIT=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2;;
  esac
done

log() { printf '\033[1;36m[dev-cluster]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[dev-cluster][ERR]\033[0m %s\n' "$*" >&2; }

for tool in kubectl kind docker bun make curl; do
  command -v "$tool" >/dev/null 2>&1 || { err "missing required tool: $tool"; exit 1; }
done

if [[ -z "$CLUSTER" ]]; then
  _clusters=$(kind get clusters 2>/dev/null || true)
  if [[ $(echo "$_clusters" | grep -c .) -eq 1 ]]; then
    CLUSTER="$(echo "$_clusters" | head -1)"
  else
    err "multiple or no kind clusters; pass -k <cluster>"
    echo "$_clusters" | sed 's/^/  /' >&2
    exit 1
  fi
fi

kubectl cluster-info >/dev/null 2>&1 || { err "no cluster reachable via kubectl"; exit 1; }

log "kind cluster: $CLUSTER"
log "namespace:    $NAMESPACE"
log "image:        $IMAGE"

if [[ $SKIP_BUILD -eq 0 ]]; then
  log "step 1/5  build v3 UI image"
  (cd "$REPO" && make build-image-v3-local)
else
  log "step 1/5  skipped build (--skip-build)"
fi

log "step 2/5  load image into kind cluster '$CLUSTER'"
kind load docker-image --name "$CLUSTER" "$IMAGE"

if [[ $SKIP_DEPLOY -eq 0 ]]; then
  log "step 3/5  apply webhook-receiver + Component CR"
  kubectl apply -f "$HERE/live-test/webhook-receiver.yaml" >/dev/null
  kubectl apply -f "$HERE/live-test/component.yaml" >/dev/null
else
  log "step 3/5  skipped deploy (--skip-deploy)"
fi

log "step 4/5  wait for operator to reconcile deployment/$SERVICE"
deadline=$(( $(date +%s) + 90 ))
while true; do
  if kubectl -n "$NAMESPACE" get "deployment/$SERVICE" >/dev/null 2>&1; then
    break
  fi
  if [[ $(date +%s) -gt $deadline ]]; then
    err "deployment/$SERVICE never appeared (operator did not reconcile Component CR within 90s)"
    exit 1
  fi
  sleep 2
done

log "          rollout restart deployment/$SERVICE to pick up the freshly loaded image"
kubectl -n "$NAMESPACE" rollout restart "deployment/$SERVICE" >/dev/null 2>&1 || true

log "          wait for webhook-receiver + $SERVICE Ready"
kubectl -n "$NAMESPACE" rollout status deployment/webhook-receiver --timeout=90s || {
  err "webhook-receiver did not become Ready"
  exit 1
}
kubectl -n "$NAMESPACE" rollout status "deployment/$SERVICE" --timeout=120s || {
  err "deployment/$SERVICE did not become Ready"
  kubectl -n "$NAMESPACE" describe "deployment/$SERVICE" | tail -60 >&2 || true
  exit 1
}

log "step 5/5  port-forward svc/$SERVICE:$BACKEND_PORT -> localhost:$LOCAL_PORT"
kubectl -n "$NAMESPACE" port-forward "svc/$SERVICE" "$LOCAL_PORT:$BACKEND_PORT" >/tmp/falcosidekick-pf.log 2>&1 &
PF_PID=$!

cleanup() {
  echo ""
  if [[ -n "${PF_PID:-}" ]] && kill -0 "$PF_PID" 2>/dev/null; then
    log "stopping port-forward (pid $PF_PID)"
    kill "$PF_PID" 2>/dev/null || true
    wait "$PF_PID" 2>/dev/null || true
  fi
  if [[ $CLEAN_ON_EXIT -eq 1 ]]; then
    log "--clean: deleting Component + webhook-receiver"
    kubectl delete --ignore-not-found -f "$HERE/live-test/component.yaml" >/dev/null 2>&1 || true
    kubectl delete --ignore-not-found -f "$HERE/live-test/webhook-receiver.yaml" >/dev/null 2>&1 || true
  else
    log "cluster resources left in place (pass --clean to tear down)"
  fi
}
trap cleanup EXIT INT TERM

for _ in $(seq 1 20); do
  if curl -sf "http://localhost:$LOCAL_PORT/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

if ! curl -sf "http://localhost:$LOCAL_PORT/healthz" >/dev/null 2>&1; then
  err "port-forward did not become reachable on http://localhost:$LOCAL_PORT within 10s"
  tail -n 20 /tmp/falcosidekick-pf.log >&2 || true
  exit 1
fi

log "backend reachable at http://localhost:$LOCAL_PORT"
log "starting UI dev server (bun run dev). Press Ctrl+C to stop."
echo ""

cd "$REPO/ui"
FALCOSIDEKICK_BACKEND="http://localhost:$LOCAL_PORT" exec bun run dev
