#!/bin/sh
set -eu
: "${ORIGIN_AUTH_SECRET:?ORIGIN_AUTH_SECRET is required}"

exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-10000}" \
  --no-proxy-headers --no-server-header
