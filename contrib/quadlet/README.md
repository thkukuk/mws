# Podman quadlet example

This directory contains an example [podman quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
unit that runs the `mws` container with both http and https enabled.

Files:
* `mws.container` - the quadlet unit
* `mws.yaml` - example mws configuration used by the unit

## Usage

```
run0 install -D -m 0644 mws.container /etc/containers/systemd/mws.container
run0 install -D -m 0644 mws.yaml /etc/mws/config.yaml
run0 mkdir -p /etc/mws/certs /srv/mws/htdocs
```

Either place `fullchain.pem`/`privkey.pem` in `/etc/mws/certs`, or remove the
`tlskey`/`tlscert` lines from `/etc/mws/config.yaml` to let mws generate a
temporary self-signed certificate on startup instead.

Then reload systemd and start the generated service:

```
run0 systemctl daemon-reload
run0 systemctl start mws.service
```

Adjust `mws.container` and `mws.yaml` to taste, e.g. the `revproxy` section,
listen addresses, or host paths.
