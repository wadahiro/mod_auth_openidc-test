#!/bin/sh

oidc_dummy_server &

valgrind -v --leak-check=yes --show-reachable=yes --error-limit=no --log-file="/var/log/valgrind.log" --tool=memcheck /usr/local/apache2/bin/httpd -X -DFOREGROUND

