# --- ETAPA 1: BUILD (Seguridad: Usamos una imagen oficial y específica) ---
FROM composer:2.7 AS builder
WORKDIR /app

# Copiamos solo dependencias para cachear capas
COPY composer.json ./
# Instalamos sin dependencias de desarrollo para reducir basura
RUN composer install --no-dev --no-scripts --no-autoloader --ignore-platform-reqs

COPY . .
RUN composer dump-autoload --optimize

# --- ETAPA 2: PRODUCCIÓN (Seguridad: Imagen liviana y sin herramientas) ---
FROM php:8.2-apache AS production

# Instalamos solo lo mínimo
RUN apt-get update && apt-get install -y \
    libzip-dev \
    && docker-php-ext-install zip \
    && rm -rf /var/lib/apt/lists/*

# CONFIGURACIÓN DE SEGURIDAD
# 1. Eliminamos la API KEY hardcodeada (Se debe pasar por Secret/Env Var en el despliegue)
# 2. Definimos Healthcheck (Soluciona CKV_DOCKER_2)
HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost/ || exit 1

WORKDIR /var/www/html

# Copiamos solo lo necesario desde builder
COPY --from=builder /app/src /var/www/html/src
COPY --from=builder /app/vendor /var/www/html/vendor
COPY --from=builder /app/index.php /var/www/html/index.php

# 3. Usuario no-root (Soluciona CKV_DOCKER_3)
RUN chown -R www-data:www-data /var/www/html
USER www-data

EXPOSE 80