# syntax=docker/dockerfile:1.7
FROM quay.io/keycloak/keycloak@sha256:82c5b7a110456dbd42b86ea572e728878549954cc8bd03cd65410d75328095d2 AS upstream

FROM maven@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237 AS build
WORKDIR /work
COPY keycloak/openbao-provider/pom.xml ./
COPY keycloak/openbao-provider/src ./src
RUN mvn -B -q -DskipTests package
COPY --from=upstream /opt/keycloak/lib/lib/main/org.keycloak.keycloak-services-25.0.6.jar /out/keycloak-services.jar
RUN jar uf /out/keycloak-services.jar -C /work/target/classes org/keycloak/protocol/RestartLoginCookie.class
RUN jar uf /out/keycloak-services.jar -C /work/target/classes org/keycloak/protocol/oidc/grants/ciba/channel/CIBAAuthenticationRequest.class
# Remove upstream key factories (generated/imported/keystore). Only the four
# explicitly registered remote factories in the provider JAR may be discovered.
RUN mkdir -p /work/remote-only/META-INF/services && \
    : > /work/remote-only/META-INF/services/org.keycloak.keys.KeyProviderFactory && \
    jar uf /out/keycloak-services.jar -C /work/remote-only META-INF/services/org.keycloak.keys.KeyProviderFactory

FROM upstream
COPY --from=build /out/keycloak-services.jar /opt/keycloak/lib/lib/main/org.keycloak.keycloak-services-25.0.6.jar
COPY --from=build /work/target/keycloak-openbao-provider-0.0.0-probe.jar /opt/keycloak/providers/marty-openbao-provider.jar
