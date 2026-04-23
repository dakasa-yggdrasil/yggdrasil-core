#!/bin/sh
# yggdrasil-core container entrypoint.
#
# Runs schema migrations before starting the service so a fresh
# deployment goes from empty Postgres -> serving traffic with one
# `docker run`. Bootstrap of the first admin and baseline catalog is
# handled by the first_run addon inside yggdrasil-core, gated on the
# YGGDRASIL_BOOTSTRAP_* env vars. See the Getting Started guide for
# the self-hosted onboarding flow.
set -e

cd /app

echo "[entrypoint] running schema migrations..."
./goose up

echo "[entrypoint] starting yggdrasil-core..."
exec ./yggdrasil-core
