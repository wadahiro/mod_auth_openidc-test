FROM golang:1.8.3-alpine
WORKDIR /go/src/github.com/wadahiro/mod_auth_openidc-test/
COPY oidc_dummy_server.go .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo oidc_dummy_server.go

FROM centos:7.3.1611
LABEL maintainer "wadahiro@gmail.com"

ENV HTTPD_VERSION=2.4.6-45.el7.centos \
    MOD_AUTH_OPENIDC_VERSION=2.3.1-1.el7.centos.x86_64 \
    MOD_AUTH_OPENIDC_SHORT_VERSION=2.3.1 \
    HIREDIS_VERSION=0.12.1-1.el7.x86_64 \
    CJOSE_VERSION=0.5.1-1.el7.centos.x86_64

RUN set -x \
  && yum install -y httpd-${HTTPD_VERSION} \
  && yum clean all 

RUN mkdir -p /tmp/work \
  && cd /tmp/work \
  && curl -L -O https://dl.fedoraproject.org/pub/epel/7/x86_64/h/hiredis-${HIREDIS_VERSION}.rpm \
  && curl -L -O https://github.com/pingidentity/mod_auth_openidc/releases/download/v2.3.0/cjose-${CJOSE_VERSION}.rpm \
  && curl -L -O https://github.com/pingidentity/mod_auth_openidc/releases/download/v${MOD_AUTH_OPENIDC_SHORT_VERSION}/mod_auth_openidc-${MOD_AUTH_OPENIDC_VERSION}.rpm \
  && yum install -y *.rpm \
  && yum clean all \
  && rm -rf /tmp/work

RUN ln -sf /dev/stdout /var/log/httpd/access_log && ln -sf /dev/stderr /var/log/httpd/error_log

COPY --from=0 /go/src/github.com/wadahiro/mod_auth_openidc-test/oidc_dummy_server /usr/local/bin/
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/*

COPY 00-mpm.conf /etc/httpd/conf.modules.d/
COPY server.conf /etc/httpd/conf.d/

EXPOSE 80
EXPOSE 8080

ENTRYPOINT [ "/usr/local/bin/docker-entrypoint.sh" ]

