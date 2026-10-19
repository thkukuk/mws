# systemd service example

This directory contains an example systemd unit that runs `mws` directly
on the host, with both http and https enabled. It is the native-service
equivalent of the podman quadlet example in `contrib/quadlet`.

Files:
* `mws.service` - the systemd unit
* `mws.yaml` - example mws configuration used by the unit

## Usage

```
run0 install -D -m 0644 mws.service /etc/systemd/system/mws.service
run0 install -D -m 0644 mws.yaml /etc/mws/config.yaml
run0 mkdir -p /etc/mws/certs /srv/mws/htdocs
```

Either place `fullchain.pem`/`privkey.pem` in `/etc/mws/certs`, or remove the
`tlskey`/`tlscert` lines from `/etc/mws/config.yaml` to let mws generate a
temporary self-signed certificate on startup instead.

Then reload systemd and start the service:

```
run0 systemctl daemon-reload
run0 systemctl enable --now mws.service
```

Adjust `mws.service` and `mws.yaml` to taste, e.g. the `revproxy` section,
listen addresses, or host paths.
