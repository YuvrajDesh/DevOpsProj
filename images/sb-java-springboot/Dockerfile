# Stage 1: build fat jar + record Maven ground truth (runtime scope)
FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src ./src
RUN mvn -q -B -DskipTests package \
 && mvn -q -B dependency:list -DincludeScope=runtime -DoutputFile=/src/gt-maven-runtime.txt \
 && mvn -q -B dependency:list -DoutputFile=/src/gt-maven-all.txt

# Stage 2: runtime image contains only the uber-jar (no pom, no lock)
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app
COPY --from=build /src/target/demo-1.0.0.jar /app/app.jar
ENTRYPOINT ["java","-jar","/app/app.jar"]
