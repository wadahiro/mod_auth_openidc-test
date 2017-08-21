#!/bin/sh

oidc_dummy_server &

httpd -DFOREGROUND

