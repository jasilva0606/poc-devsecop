FROM php:8.2-apache

# ERROR: Dejamos el token de una API hardcodeado (Gitleaks/Trivy)
ENV CLIMA_API_KEY="AIzaSyA1234567890-SECRET-KEY"

# ERROR: Instalamos herramientas innecesarias que aumentan superficie de ataque
RUN apt-get update && apt-get install -y git wget curl unzip

# Copiamos todo (incluyendo basura de dev)
COPY . /var/www/html/

# ERROR: Corremos como ROOT (Checkov/Trivy marcarán esto)
# EXPOSE 80
CMD ["apache2-foreground"]