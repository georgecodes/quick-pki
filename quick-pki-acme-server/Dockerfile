FROM maven:3.9.9-eclipse-temurin-17 AS build
WORKDIR /workspace
COPY pom.xml .
COPY quick-pki-lib/pom.xml quick-pki-lib/pom.xml
COPY quick-pki-acme-server/pom.xml quick-pki-acme-server/pom.xml
COPY quick-pki-cert-api/pom.xml quick-pki-cert-api/pom.xml
RUN mvn -pl quick-pki-acme-server -am dependency:go-offline
COPY quick-pki-lib quick-pki-lib
COPY quick-pki-acme-server quick-pki-acme-server
RUN mvn -pl quick-pki-acme-server -am package -DskipTests

FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /workspace/quick-pki-acme-server/target/quick-pki-acme-server-*-SNAPSHOT.jar /app/quick-pki-acme-server.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/quick-pki-acme-server.jar"]
