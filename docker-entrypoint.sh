#!/bin/sh

sed -i -e "s|%OIDC_SERVER_URL%|$OIDC_SERVER_URL|g" /etc/httpd/conf.d/server.conf
sed -i -e "s|%OIDC_REDIRECT_URL%|$OIDC_REDIRECT_URL|g" /etc/httpd/conf.d/server.conf
sed -i -e "s|%OIDC_SERVER_URL%|$OIDC_SERVER_URL|g" /usr/local/apache2/conf.d/server.conf
sed -i -e "s|%OIDC_REDIRECT_URL%|$OIDC_REDIRECT_URL|g" /usr/local/apache2/conf.d/server.conf

oidc_dummy_server -server_url $OIDC_SERVER_URL -redirect_url $OIDC_REDIRECT_URL &

if [ -n "$HTTPD_SINGLE_PROCESS" ]; then
    OPTION="-X"
fi

if [ -n "$HTTPD_DEBUG" ]; then
    /usr/local/apache2/bin/httpd -V
    valgrind -v --leak-check=yes --show-reachable=yes --error-limit=no --log-file="/var/log/valgrind.log" --tool=memcheck /usr/local/apache2/bin/httpd $OPTION -DFOREGROUND

else
    /usr/sbin/httpd -V
    /usr/sbin/httpd $OPTION -DFOREGROUND
fi


