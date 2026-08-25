#!/bin/bash

set -e

mkdir -p /opt/cassandra/data /var/lib/cassandra
chown -R cassandra:cassandra /opt/cassandra /var/lib/cassandra

cd /var/lib/cassandra
su cassandra -s /bin/bash -c "PATH=$PATH cassandra -f" &
CASSANDRA_PID=$!

echo "Waiting for Cassandra..."

until cqlsh 127.0.0.1 9042 -e "SELECT * FROM system.local" >/dev/null 2>&1
do
    sleep 2
done

echo "Cassandra is ready."
echo "Running init.cql..."

cqlsh 127.0.0.1 9042 -f /init.cql

echo "Initialization completed."

wait $CASSANDRA_PID
