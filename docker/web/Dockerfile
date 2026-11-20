FROM php:8.5-apache
ARG APP_UID=1000

# pdo_pgsql is the only extra extension. Unused Apache modules are disabled
# (least functionality); the worker user matches the host developer UID so that
# 0600 secret files and logs/ stay private to one account.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpq-dev \
 && docker-php-ext-install pdo_pgsql \
 && rm -rf /var/lib/apt/lists/* \
 && a2enmod ssl headers \
 && a2dismod -f autoindex status \
 && a2dissite 000-default \
 && a2disconf serve-cgi-bin \
 && useradd --uid "${APP_UID}" --no-create-home --shell /usr/sbin/nologin grantsweb \
 && install -d -o grantsweb -g grantsweb -m 700 /var/lib/grants/sessions \
 && cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"

COPY php.ini "$PHP_INI_DIR/conf.d/zz-grants.ini"
COPY vhost.conf /etc/apache2/sites-available/grants.conf
RUN a2ensite grants

ENV APACHE_RUN_USER=grantsweb APACHE_RUN_GROUP=grantsweb
WORKDIR /srv/grants
