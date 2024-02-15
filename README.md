# mws
Mini-Webserver (mws) - small webserver for static web pages with reverse proxy
support written in go

## Intro
This webserver serves static web pages via http and/or https. Additional it
can act as reverse proxy.
If no certificates are specified, temporary ones will be created on the fly for the local hostname and localhost.

The server listens by default only on port 80. If only https should be provided,
this can be disabled with an empty `--http=""` option.

### Reverse Proxy



## Usage
```
  mws [flags]
```

### Flags
  * `-c`, `--config string` configuration file in yaml format
  * `-d`, `--dir string`    directory to read files from (default ".")
  * `-h`, `--help`          help for mws
  * `--http string`         address to listen on for http (default ":80")
  * `--https string`        address to listen on for https
  * `--timeout-read int`    timeout in seconds for http read (default 5)
  * `--timeout-write int`   timeout in seconds for http write (default 10)
  * `--tls-cert string`     path to the certificate file for https
  * `--tls-key string`      path to the key file for https
  * `-v`, `--version`       version for mws

### Configuration File

## Container

### Building your own container

To build your own container image:
```
sudo podman build --build-arg VERSION="$(cat VERSION)" --build-arg BUILDTIME=$(date +%Y-%m-%dT%TZ) -t mws .
```

###

Run the container image with http and https ports open, certificate is generated on the fly in memory on start:
```
sudo podman run -p 80:80 -p 443:443 thkukuk/mws --https :443
```


To specify a directory from where the static webpages are used:
```
sudo podman run -p 80:80 -p 443:443 -v /srv/www:/srv/www --rm --name mws thkukuk/mws --https :443 --dir /srv/www/htdocs
```
In this example we expect that on the host OS we have a directory structure below /srv/www which contains the web pages in the directory htdocs.
