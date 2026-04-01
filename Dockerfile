# Étape 1 : utiliser l'image officielle OpenJDK 17
FROM eclipse-temurin:17-jdk-alpine

# Étape 2 : définir le répertoire de travail dans le conteneur
WORKDIR /app

# Étape 3 : copier le JAR compilé dans le conteneur
# Le JAR est généré par "mvn clean package" dans target/
COPY target/authentification-0.0.1-SNAPSHOT.jar app.jar

# Étape 4 : exposer le port 8080
EXPOSE 8080

# Étape 5 : démarrer l'application Spring Boot
ENTRYPOINT ["java", "-jar", "/app/app.jar"]