#!/usr/bin/env bash
# Usage: check_health.sh https://zeroday-web.onrender.com https://zeroday-api.onrender.com
set -u
for url in "$@"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 60 "$url/health")
  echo "$url/health -> $code"
done
