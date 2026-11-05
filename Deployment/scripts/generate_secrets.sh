#!/usr/bin/env bash
# Prints strong random values for the environment variables used by compose/Render.
set -euo pipefail
rnd() { openssl rand -base64 "$1" | tr -d '\n=+/' | cut -c1-"$2"; }
echo "JWT_KEY=$(rnd 48 64)"
echo "ML_API_KEY=$(rnd 32 40)"
echo "SA_PASSWORD=Aa1!$(rnd 24 24)"
echo "ADMIN_PASSWORD=Aa1#$(rnd 18 18)"
