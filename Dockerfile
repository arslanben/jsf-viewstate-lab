FROM tomcat:9-jdk8-temurin

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl; \
    rm -rf /var/lib/apt/lists/*

ENV CATALINA_HOME=/usr/local/tomcat \
    APP_HOME=/usr/local/tomcat/webapps/ROOT \
    M2=https://repo1.maven.org/maven2

RUN rm -rf "$CATALINA_HOME"/webapps/* && \
    mkdir -p "$APP_HOME"/WEB-INF/classes "$APP_HOME"/WEB-INF/lib

COPY app/src/main/java/ /build/java/
COPY app/src/main/webapp/ /build/webapp/

RUN set -eux; \
    curl -fsSL -o "$APP_HOME"/WEB-INF/lib/javax.faces-2.2.20.jar \
        "$M2"/org/glassfish/javax.faces/2.2.20/javax.faces-2.2.20.jar; \
    curl -fsSL -o "$APP_HOME"/WEB-INF/lib/commons-beanutils-1.9.2.jar \
        "$M2"/commons-beanutils/commons-beanutils/1.9.2/commons-beanutils-1.9.2.jar; \
    curl -fsSL -o "$APP_HOME"/WEB-INF/lib/commons-logging-1.2.jar \
        "$M2"/commons-logging/commons-logging/1.2/commons-logging-1.2.jar; \
    curl -fsSL -o "$APP_HOME"/WEB-INF/lib/commons-collections-3.1.jar \
        "$M2"/commons-collections/commons-collections/3.1/commons-collections-3.1.jar; \
    javac -encoding UTF-8 \
        -cp "$CATALINA_HOME"/lib/servlet-api.jar:"$APP_HOME"/WEB-INF/lib/javax.faces-2.2.20.jar \
        -d "$APP_HOME"/WEB-INF/classes \
        $(find /build/java -name '*.java'); \
    cp -r /build/webapp/. "$APP_HOME"/; \
    rm -rf /build

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
