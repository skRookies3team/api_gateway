FROM eclipse-temurin:17-jre-jammy
WORKDIR /app
COPY build/libs/*.jar api-gateway.jar
ENTRYPOINT ["java","-XX:+UseContainerSupport","-XX:MaxRAMPercentage=75","-jar","api-gateway.jar"]