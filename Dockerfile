FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

RUN apk add --no-cache curl

COPY target/server.jar app.jar

ENV UUID=da21e461-ce27-4098-815b-d575d1b351b7 \
    NEZHA_SERVER="" \
    NEZHA_PORT="" \
    NEZHA_KEY="" \
    DOMAIN="" \
    KOMARI_SERVER="" \
    KOMARI_KEY="" \
    SUB_PATH="subb" \
    NAME="" \
    WSPATH="" \
    SERVER_PORT=3000 \
    AUTO_ACCESS="false" \
    DEBUG="false"

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${SERVER_PORT}/ || exit 1

CMD ["java", "-jar", "app.jar"]
