FROM eclipse-temurin:21-jre-jammy

# Добавил net-tools, чтобы у тебя всегда была возможность выполнить netstat внутри контейнера
RUN apt-get update && apt-get install -y python3 python3-pip net-tools && \
    ln -s /usr/bin/python3 /usr/bin/python && \
    rm -rf /var/lib/apt/lists/*

COPY apache-cassandra-6.0-alpha2-SNAPSHOT-bin.tar.gz /opt/

RUN tar -xzf /opt/apache-cassandra-6.0-alpha2-SNAPSHOT-bin.tar.gz -C /opt && \
    mv /opt/apache-cassandra-6.0-alpha2-SNAPSHOT /opt/cassandra && \
    groupadd -r cassandra && useradd -r -g cassandra cassandra && \
    chown -R cassandra:cassandra /opt/cassandra

# Переключаемся на пользователя cassandra
USER cassandra

ENV PATH="/opt/cassandra/bin:${PATH}"

# Настраиваем сеть и раскомментируем блок Accord транзакций через sed
# Исправленный блок sed для Dockerfile
RUN sed -i \
  -e 's/^rpc_address:.*/rpc_address: 0.0.0.0/' \
  -e 's/^listen_address:.*/listen_address: 127.0.0.1/' \
  -e 's/^# broadcast_rpc_address:.*/broadcast_rpc_address: cassandra/' \
  -e 's/^#accord:/accord:/' \
  -e 's/^#  enabled: false/  enabled: true/' \
  -e 's|^#  journal_directory:.*|  journal_directory: /opt/cassandra/data/journal|' \
  /opt/cassandra/conf/cassandra.yaml

# Создаем директорию для журнала заранее, чтобы у Accord не было проблем с доступом
RUN mkdir -p /opt/cassandra/data/journal

EXPOSE 9042 7000 7199
CMD ["cassandra", "-f"]