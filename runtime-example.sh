#!/usr/bin/env sh
set -eu
# Example hardened local-only source analyzer. The application source is mounted read-only.
docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges=true \
  --pids-limit 128 \
  --memory 512m \
  --cpus 1 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m \
  -v "$(pwd):/workspace:ro" \
  dolossec-runtime -r /workspace -q
