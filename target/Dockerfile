# CVE-2026-114938 - alvo de laboratorio
#
# A tag oficial openjdk:17.0.6 NAO existe no Docker Hub (404).
# Passe BASE_IMAGE para testar outro runtime (ex.: build corrigido).
ARG BASE_IMAGE=eclipse-temurin:17.0.6_10-jdk
FROM ${BASE_IMAGE}

WORKDIR /app
COPY DecodeServer.java .
RUN javac -d /app DecodeServer.java

# Workaround opcional, aplicado em runtime:
#   docker run -e JAVA_OPTS="-XX:-UseBASE64Intrinsics" ...
ENV JAVA_OPTS=""

EXPOSE 8080
CMD ["sh", "-c", "exec java $JAVA_OPTS -cp /app DecodeServer"]
