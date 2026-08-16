FROM php:8.3-apache

RUN docker-php-ext-install pdo_mysql \
    && a2enmod rewrite

COPY . /var/www/html
RUN chown -R www-data:www-data /var/www/html/public/uploads \
    && mkdir -p /tmp/vulnapp-pages \
    && cp -r /var/www/html/src/pages/* /tmp/vulnapp-pages/

COPY docker/apache.conf /etc/apache2/conf-available/vulnapp.conf
RUN a2enconf vulnapp

EXPOSE 80