FROM openjdk:17-jdk-slim
WORKDIR /app
COPY build/libs/*.jar api-gateway.jar
ENTRYPOINT ["java","-jar","api-gateway.jar"]
