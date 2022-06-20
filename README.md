# mws
Mini-Webserver (mws) - small webserver for static web pages supporting http and https written in go

## Intro
This webserver serves static web pages via http and/or https.
If no certificates are specified, temporary ones will be created on the fly for the local hostname and localhost.

The server listens by default only on port 80. If only https should be provided,
this can be disabled with an empty `--http=""` option.

## Usage:
```
  mws [flags]
```

### Flags:
  * `-d`, `--dir string`          directory to read files from (default ".")
  * `-h`, `--help`                help for mws
  *     `--http string`         address to listen on for http (default ":80")
  *     `--https string`        address to listen on for https
  *     `--timeout-read int`    timeout in seconds for http read (default 5)
  *     `--timeout-write int`   timeout in seconds for http write (default 10)
  *     `--tls-cert string`     path to the certificate file for https
  *     `--tls-key string`      path to the key file for https
  * `-v`, `--version`             version for mws

