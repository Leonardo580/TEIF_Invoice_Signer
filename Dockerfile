# Stage 1: Build
FROM  maven:3.9-amazoncorretto-24-alpine as builder
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src ./src
RUN mvn package -DskipTests -B
RUN ls -l /app/target


# Stage 2: Run
FROM amazoncorretto:24-alpine
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar
COPY --from=builder /app/target/libs /app/libs
COPY .env ./.env
EXPOSE 10001
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
