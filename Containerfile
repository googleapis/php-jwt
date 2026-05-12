ARG PHP_VERSION=8.5
ARG COMPOSER_VERSION=latest
ARG NODE_VERSION=current

FROM docker.io/composer:${COMPOSER_VERSION} AS composer

FROM docker.io/node:${NODE_VERSION}-alpine AS node

FROM docker.io/php:${PHP_VERSION}-fpm-alpine AS app

WORKDIR /srv/app

# Update base
RUN apk update && apk upgrade

# persistent / runtime deps
RUN apk add --no-cache \
		openssl \
	;

# TODO: Remove hardcoded imagick version after stable-release
RUN set -eux; \
	apk add --no-cache --virtual .build-deps \
		$PHPIZE_DEPS \
		libsodium-dev \
	; \
	\
	docker-php-ext-install -j$(nproc) \
		sodium \
	; \
	\
	runDeps="$( \
		scanelf --needed --nobanner --format '%n#p' --recursive /usr/local/lib/php/extensions \
			| tr ',' '\n' \
			| sort -u \
			| awk 'system("[ -e /usr/local/lib/" $1 " ]") == 0 { next } { print "so:" $1 }' \
	)"; \
	apk add --no-cache --virtual .app-phpexts-rundeps $runDeps; \
	\
	apk del .build-deps

RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"

# Add dev-tools
COPY --from=composer /usr/bin/composer /usr/bin/composer
ENV PATH="${PATH}:/root/.composer/vendor/bin:/srv/app/vendor/bin"
COPY --from=node /usr/lib /usr/lib
COPY --from=node /usr/local/lib /usr/local/lib
COPY --from=node /usr/local/include /usr/local/include
COPY --from=node /usr/local/bin /usr/local/bin
COPY --from=node /opt /opt

COPY . .
RUN rm -f .env .env.*

RUN chown -R www-data:root /srv/app; \
    chmod -R g=u /srv/app
