# --- ETAPA 1: BUILD ---
FROM composer:2.7 AS builder
WORKDIR /app

# Copiamos archivos de dependencias
COPY composer.json ./
# Instalamos dependencias (Snyk detectará que Guzzle 7.4.5 es vulnerable aquí)
RUN composer install --no-dev --no-scripts --no-autoloader --ignore-platform-reqs

# Copiamos el resto del código (esto incluye la carpeta src)
COPY . .
RUN composer dump-autoload --optimize

# --- ETAPA 2: PRODUCCIÓN ---
FROM php:8.2-apache AS production

# Instalamos solo lo mínimo necesario
RUN apt-get update && apt-get install -y \
    libzip-dev \
    && docker-php-ext-install zip \
    && rm -rf /var/lib/apt/lists/*

# HEALTHCHECK para cumplir con Checkov
HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost/ || exit 1

WORKDIR /var/www/html

# COPIAS ESTRATÉGICAS:
# 1. Copiamos el contenido de src directamente a la raíz de Apache
COPY --from=builder /app/src/index.php /var/www/html/index.php
# 2. Copiamos la carpeta vendor para que las librerías funcionen
COPY --from=builder /app/vendor /var/www/html/vendor

# Permisos y usuario no-root para seguridad
RUN chown -R www-data:www-data /var/www/html
USER www-data

EXPOSE 80