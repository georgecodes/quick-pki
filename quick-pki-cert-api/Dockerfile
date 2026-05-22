FROM maven:3.9.9-eclipse-temurin-17 AS build
WORKDIR /workspace
COPY pom.xml .
COPY quick-pki-lib/pom.xml quick-pki-lib/pom.xml
COPY quick-pki-cert-api/pom.xml quick-pki-cert-api/pom.xml
RUN mvn -pl quick-pki-cert-api -am dependency:go-offline
COPY quick-pki-lib quick-pki-lib
COPY quick-pki-cert-api quick-pki-cert-api
RUN mvn -pl quick-pki-cert-api -am package -DskipTests

FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /workspace/quick-pki-cert-api/target/quick-pki-cert-api-*-SNAPSHOT.jar /app/quick-pki-cert-api.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/quick-pki-cert-api.jar"]
