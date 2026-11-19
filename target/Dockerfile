# CVE-2026-114938 - lab target
#
# The official openjdk:17.0.6 tag does NOT exist on Docker Hub (404).
# Pass BASE_IMAGE to test another runtime (e.g. a patched build).
ARG BASE_IMAGE=eclipse-temurin:17.0.6_10-jdk
FROM ${BASE_IMAGE}

WORKDIR /app
COPY DecodeServer.java .
RUN javac -d /app DecodeServer.java

# Optional workaround, applied at runtime:
#   docker run -e JAVA_OPTS="-XX:-UseBASE64Intrinsics" ...
ENV JAVA_OPTS=""

EXPOSE 8080
CMD ["sh", "-c", "exec java $JAVA_OPTS -cp /app DecodeServer"]
