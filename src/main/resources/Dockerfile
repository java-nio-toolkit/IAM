FROM cassandra:6.0-alpha2

COPY init.cql /init.cql

RUN sed -i \
    -e 's/^rpc_address:.*/rpc_address: 0.0.0.0/' \
    -e 's/^listen_address:.*/listen_address: 127.0.0.1/' \
    -e 's/^# broadcast_rpc_address:.*/broadcast_rpc_address: cassandra/' \
    -e 's/^#accord:/accord:/' \
    -e 's/^#  enabled: false/  enabled: true/' \
    -e 's|^#  journal_directory:.*|  journal_directory: /var/lib/cassandra/data/journal|' \
    /etc/cassandra/cassandra.yaml && \
    mkdir -p /var/lib/cassandra/data/journal /opt/cassandra/data && \
    chown -R cassandra:cassandra /var/lib/cassandra /opt/cassandra

EXPOSE 7000 7199 9042
