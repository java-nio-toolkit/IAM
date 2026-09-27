#!/bin/bash
set -e

(
    until cqlsh -e "SELECT release_version FROM system.local" >/dev/null 2>&1; do
        sleep 2
    done
    cqlsh -f /init.cql
) &

exec docker-entrypoint.sh "$@"
