# Stage 1: Build/Dependency stage
FROM php:8.3-alpine AS builder

WORKDIR /var/www/html

# Instalamos dependencias mínimas para construir el proyecto
# Alpine usa 'apk' en lugar de 'apt'
RUN apk add --no-cache \
    git \
    unzip \
    libzip-dev

# Composer oficial
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Optimizamos caché de capas
COPY composer.json composer.lock ./
RUN composer install --no-dev --optimize-autoloader --no-scripts

# ---

# Stage 2: Final Production Image
FROM php:8.3-fpm-alpine

LABEL maintainer="jasilva"
LABEL description="Weather API Enterprise Secure Image"

WORKDIR /var/www/html

# 1. Seguridad: Actualizamos el SO y solo instalamos lo mínimo indispensable
# 2. Instalamos 'fcgi' necesario para el HEALTHCHECK en Alpine
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache libzip fcgi && \
    rm -rf /var/cache/apk/*

# Copiamos solo lo necesario del builder
COPY --from=builder /var/www/html/vendor ./vendor
COPY . .

# Ajustamos permisos para el usuario por defecto de PHP en Alpine
RUN chown -R www-data:www-data /var/www/html

# Seguridad: Ejecutar como usuario sin privilegios
USER www-data

EXPOSE 9000

# HEALTHCHECK optimizado para Alpine
# Usamos cgi-fcgi para validar que PHP-FPM está respondiendo realmente
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD SCRIPT_NAME=/ping SCRIPT_FILENAME=/ping REQUEST_METHOD=GET cgi-fcgi -bind -connect 127.0.0.1:9000 || exit 1

CMD ["php-fpm"]