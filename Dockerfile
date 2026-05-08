# Stage 1: Build/Dependency stage
FROM php:8.3-fpm-bullseye AS builder

WORKDIR /var/www/html

# Instalamos dependencias de sistema necesarias para composer y extensiones
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    unzip \
    libzip-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Instalamos Composer de forma segura
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Copiamos solo archivos de dependencias para aprovechar la caché de Docker
COPY composer.json composer.lock ./

# Instalamos dependencias de producción
RUN composer install --no-dev --optimize-autoloader --no-scripts

# ---

# Stage 2: Final Production Image
FROM php:8.3-fpm-bullseye

LABEL maintainer="tu-nombre"
LABEL description="Weather API Production Image"

WORKDIR /var/www/html

# SOLUCIÓN TRIVY: Actualizamos el SO para parchar CVE-2026-33845
# Ejecutamos update y upgrade en una sola capa y limpiamos caché
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    libzip4 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copiamos el código y las dependencias desde el builder
COPY --from=builder /var/www/html/vendor ./vendor
COPY . .

# Ajustamos permisos para que el usuario non-root pueda trabajar
RUN chown -R www-data:www-data /var/www/html

# Configuración de seguridad: Usuario non-root
USER www-data

# Exponemos el puerto estándar de PHP-FPM
EXPOSE 9000

# HEALTHCHECK para cumplir con Checkov y asegurar disponibilidad
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD cgi-fcgi -bind -connect 127.0.0.1:9000 || exit 1

CMD ["php-fpm"]