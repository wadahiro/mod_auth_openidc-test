# Testing [mod_auth_openidc](https://github.com/pingidentity/mod_auth_openidc) using dummy OP

## Description 
This project provides pre-configured [mod_auth_openidc](https://github.com/pingidentity/mod_auth_openidc) environment using dummy OP as Docker container for testing and deubugging.


## How to build

Run `./build.sh`. It builds Docker container.


## How to use

### Run with [distributed version](https://github.com/pingidentity/mod_auth_openidc/releases)

```
docker run --rm -it \
  -p 80:80 \
  -p 8080:8080 \
  -e OIDC_SERVER_URL=http://yourhost:8080 \
  -e OIDC_REDIRECT_URL=http://yourhost/callback \
  wadahiro/mod_auth_openidc-test 
```

### Run with source build version (+[Valgrind](http://valgrind.org/))

```
docker run --rm -it \
  -p 80:80 \
  -p 8080:8080 \
  -e HTTPD_DEBUG=1 \
  -e HTTPD_SINGLE_PROCESS=1 \
  -e OIDC_SERVER_URL=http://yourhost:8080 \
  -e OIDC_REDIRECT_URL=http://yourhost/callback \
  wadahiro/mod_auth_openidc-test 
```

## License
* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)

## Author
[Hiroyuki Wada](https://github.com/wadahiro)

