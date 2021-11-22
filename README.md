# iceberg

## Description

**iceberg** is a file server that uses client certificate authentication and policy-based access control.  iceberg requires the use of client certificates verified with the certificate authority chain configured at startup.

Iceberg is built in [Go](https://golang.org/). Iceberg uses the [net/http](https://pkg.go.dev/net/http) and [crypto/tls](https://pkg.go.dev/crypto/tls#Config) packages in the Go standard library to secure communication.  By default, iceberg supports TLS 1.0 to 1.3 and all the [CipherSuites](https://pkg.go.dev/crypto/tls?tab=doc#CipherSuites) implemented by `net/http`, excluding those with known security issues.  The TLS configuration can be modified using command line flags.

Iceberg is an alternative to configuring the [Apache HTTP Server](https://httpd.apache.org/) or [NGINX](https://www.nginx.com/) to serve files while requiring client certificates.  Iceberg does not attempt to be on parity with other file servers, but is designed to be a file server that is simple to manage and secure by default.

## Usage

The `iceberg` program has 5 sub commands: `defaults`, `help`, `serve`, `validate-access-policy`, and `version`.  Use `iceberg serve` to launch the server and `iceberg validate-access-policy` to validate a policy file.  Use `iceberg defaults [tls-cipher-suites|tls-curve-preferences]` to show default configuration.  Use `iceberg version` to show the current version.

Below is the usage for the `iceberg serve` command.

```text
start the iceberg server

Usage:
  iceberg serve [flags]

Flags:
  -p, --access-policy string              path to the policy file.
  -f, --access-policy-format string       format of the policy file (default "json")
  -a, --addr string                       address that iceberg will listen on (default ":8080")
      --behavior-not-found string         default behavior when a file is not found.  One of: redirect,none (default "none")
      --client-ca string                  path to CA bundle for client authentication
      --client-ca-format string           format of the CA bundle for client authentication, either pkcs7 or pem (default "pkcs7")
      --client-crl string                 path to CRL bundle for client authentication
      --client-crl-format string          format of the CRL bundle for client authentication, either der, der.zip, or pem (default "der")
      --dry-run                           exit after checking configuration
  -h, --help                              help for serve
      --keylog string                     path to the key log output.  Also requires unsafe flag.
  -l, --log string                        path to the log output.  Defaults to stdout. (default "-")
      --ocsp-http-timeout duration        the maximum amount of time before OCSP http requests timeout (default 30s)
      --ocsp-refresh-min duration         the minimum amount of time to wait before a refresh can occur (default 5m0s)
      --ocsp-refresh-ratio float          the amount of time to wait for renewal between OCSP production and next update (default 0.8)
      --ocsp-renew-interval duration      interval to run OCSP renewal (default 5m0s)
      --ocsp-server                       enable OCSP checking on the server certificate
      --public-location string            the public location of the server used for redirects
      --redirect string                   address that iceberg will listen to and redirect requests to the public location
  -r, --root string                       path to the document root served
      --server-cert string                path to server public cert
      --server-key string                 path to server private key
  -t, --template string                   path to the template file used during directory listing
      --timeout-idle string               maximum amount of time to wait for the next request when keep-alives are enabled (default "5m")
      --timeout-read string               maximum duration for reading the entire request (default "15m")
      --timeout-write string              maximum duration before timing out writes of the response (default "5m")
      --tls-cipher-suites string          list of supported cipher suites for TLS versions up to 1.2 (TLS 1.3 is not configureable)
      --tls-curve-preferences string      curve preferences (default "X25519,CurveP256,CurveP384,CurveP521")
      --tls-max-version string            maximum TLS version accepted for requests (default "1.3")
      --tls-min-version string            minimum TLS version accepted for requests (default "1.0")
      --tls-prefer-server-cipher-suites   prefer server cipher suites
      --unsafe                            allow unsafe configuration
```

### Network Encryption

**iceberg** requires the use of a server certificate and client certificate authentication.  The server certificate is loaded from a PEM-encoded x509 key pair using the [LoadX509KeyPair](https://golang.org/pkg/crypto/tls/#LoadX509KeyPair) function.  The location of the key pair is specified using the `--server-cert` and `--server-key` command line flags.

The client certificate authorities can be loaded from a [PKCS#7](https://en.wikipedia.org/wiki/PKCS) or PEM-encoded file.  The [Parse](https://pkg.go.dev/go.mozilla.org/pkcs7#Parse) function in [go.mozilla.org/pkcs7](https://pkg.go.dev/go.mozilla.org/pkcs7) is used to parse the PKCS#7-encoded data loaded from a `.p7b` file.  The [AppendCertsFromPEM](https://pkg.go.dev/crypto/x509#CertPool.AppendCertsFromPEM) method is used to parse PEM-encoded data loaded from a `.pem` file.  The location of the client certificate authorities is specified using the `client-ca` and `client-ca-format` command line flags.

You can use the `tls-*` flags to customize the server TLS configuration.  Options are very limited for [TLS 1.3](https://github.com/golang/go/issues/29349).

For example, you could configure the server to only support TLS version `1.2` and specific ciphers using `--tls-min-version`, `--tls-max-version`, and `--tls-cipher-suites`.

```shell
iceberg serve ... --tls-min-version 1.2 --tls-max-version 1.2 --tls-cipher-suites 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'
```

Mozilla keeps a [Security/Server Side TLS](https://wiki.mozilla.org/Security/Server_Side_TLS) document up to date on the best practices for configuring a server for TLS.

### Access Policy Document

An access policy document is a list of statements that are evaluate when determining whether a user can access a given file path.  By default, users have no privileges.  The access policy document can be serialized as a JSON or YAML document.

```json
{
  "statements": [...]
}
```

The policy statements are evaluated sequentially.  If the first policy statement allows access, the other statements are still evaluated.  If any statement denies access, then the user is denied access.

Each statement requires the `effect`, `paths`, and `users`/`not_users` to be set.  The id is optional and not used during evaluation.  The effect is either `allow` or `deny`.

```json
{
  "id": "DefaultAllow",
  "effect": "allow",
  "paths": [...],
  "users": [...],
  "not_users": [],
}
```

The values for `paths` includes an array of paths from the root directory as set during startup, e.g., `/shared`.  Paths can start or end with a `wildcard`, eg., `/shared/*` or `*.jpg`.

```json
{
  "paths": [
    "/shared/",
    "/shared/*"
  ]
}
```

The value for `paths` can be set to `["*"]` to apply to all file paths.

```json
{
  "paths": ["*"]
}
```

The values included in `users` or `not_users` includes an array of distinguished names derived from the the subject of the client certificate provided by the connecting client.  The value of `not_users` means the statement effect is applied to any user not in the array.  For example.

```json
{
  "users": [
    "/C=US/O=Atlantis/OU=Atlantis Digital Service/OU=CONTRACTOR/CN=LAST.FIRST.MIDDLE.ID"
  ]
}
```

The value for `users` can be set to `["*"]` to apply to all users.

```json
{
  "users": ["*"]
}
```

### Directory Listing Template

The template provided during server startup is used to render directory listings using the native Go template rendering engine in the [html/template](https://golang.org/pkg/html/template/) package.  The template is provided the following context.

```go
struct {
  Up        string
  Directory string
  Files     []struct {
    ModTime string
    Size    int64
    Type    string
    Path    string
  }
})
```

In addition to the default functions available, the `prefix` and `suffix` template functions are also available.  For example, the suffix function can be used to conditionally write an html element based on the file extension.

```html
{{if .Path | suffix ".mp4"}}Video{{else}}Other{{end}}
```

## Examples

Below are the example commands and files needed to run a server that, by default allows access to all files, but limits access to the `/secure` path to a limited set of users identified by their client certificate subject distinguished name.

```shell
iceberg serve \
--access-policy examples/conf/example.json \
--client-ca temp/certs.p7b \
--root examples/public \
--server-cert temp/server.crt \
--server-key temp/server.key \
--template examples/conf/template.html \
--behavior-not-found redirect
```

The below policy statement allows access to any authenticated user and then limits access to `/secure` to a limited set of users.

```json
{
  "statements": [
    {
      "id": "DefaultAllow",
      "effect": "allow",
      "paths": [
        "*"
      ],
      "users": [
        "*"
      ]
    },
    {
      "id": "ProtectSecure",
      "effect": "deny",
      "paths": [
        "/secure",
        "/secure/*"
      ],
      "not_users": [
        "/C=US/O=Atlantis/OU=Atlantis Digital Service/OU=CONTRACTOR/CN=LAST.FIRST.MIDDLE.ID",
      ]
    }
  ]
}
```

## Building

**iceberg** is written in pure Go, so the only dependency needed to compile the server is [Go](https://golang.org/).  Go can be downloaded from <https://golang.org/dl/>.

This project uses [direnv](https://direnv.net/) to manage environment variables and automatically adding the `bin` and `scripts` folder to the path.  Install direnv and hook it into your shell.  The use of `direnv` is optional as you can always call iceberg directly with `bin/iceberg`.

If using `macOS`, follow the `macOS` instructions below.

To build a binary for your local operating system you can use `make bin/iceberg`.  To build for a release, you can use `make build_release`.  Additionally, you can call `go build` directly to support specific use cases.

### macOS

You can install `go` on macOS using homebrew with `brew install go`.

To install `direnv` on `macOS` use `brew install direnv`.  If using bash, then add `eval \"$(direnv hook bash)\"` to the `~/.bash_profile` file .  If using zsh, then add `eval \"$(direnv hook zsh)\"` to the `~/.zshrc` file.

## Development

To get started you will need to edit the `/etc/hosts` file on your machine to have this entry:

```txt
127.0.0.1   iceberglocal
```

To connect to the server you need a client certificate and key pair, so create that file first:

```sh
make temp/client.p12
```

To run the example included in this repository start by running the server in docker:

```sh
make docker_build docker_serve_example
```

Now connect to the server with cURL to view the `index.html` file or the contents of the `allowed/` directory:

```sh
curl --cacert ./temp/ca.crt --key ./temp/client.key --cert ./temp/client.crt https://iceberglocal:8080/index.html
curl --cacert ./temp/ca.crt --key ./temp/client.key --cert ./temp/client.crt https://iceberglocal:8080/allowed/
```

To view files based on the contents of the `conf/example.json` file:

```sh
curl --cacert ./temp/ca.crt --key ./temp/client.key --cert ./temp/client.crt https://iceberglocal:8080/allowed/a.txt
curl --cacert ./temp/ca.crt --key ./temp/client.key --cert ./temp/client.crt https://iceberglocal:8080/allowed/b.txt
```

Other directories and files will be explicitly denied based on the same example policy:

```sh
curl --cacert ./temp/ca.crt --key ./temp/client.key --cert ./temp/client.crt https://iceberglocal:8080/allowed/123.abc
curl --cacert ./temp/ca.crt --key ./temp/client.key --cert ./temp/client.crt https://iceberglocal:8080/denied/
curl --cacert ./temp/ca.crt --key ./temp/client.key --cert ./temp/client.crt https://iceberglocal:8080/denied/a.txt
curl --cacert ./temp/ca.crt --key ./temp/client.key --cert ./temp/client.crt https://iceberglocal:8080/denied/b.txt
curl --cacert ./temp/ca.crt --key ./temp/client.key --cert ./temp/client.crt https://iceberglocal:8080/denied/123.abc
```

### Firefox

You may consider using a web browser to view the files. In this case you need to load the Certificate Authority and identity file
into the firefox Certificate Manager. Browse to "about:preferences#privacy" and search for the section labelled "Certificates".
Use the "View Certificates" button to open the Certificate Manager.

In the "Authorities" tab use the "Import..." button to load the `temp/ca.crt` file.  When asked select
"Trust this CA to identify websites." and then continue by selecting "OK".

In the "Your Certificates" tab use the "Import..." button to load the `temp/client.p12` file.  There is no password to enter
so select the "OK" button immediately.

Now you may browse to the website at <https://iceberglocal:8080>.

### Key Logging

Key logging should only be used in development since it compromises the security of TLS.  You can output TLS master secrets in the [NSS Key Log Format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format) by using the `--unsafe` and `--keylog KEYLOG` flags.  The newly created file can be used by [Wireshark](https://wiki.wireshark.org/TLS) or other applications to decrypt TLS traffic.

### OCSP Stapling

**NOTE:** At this time this will not work with Docker.

OCSP is the preferred method of managing certificate revocation as certificate revocation lists can get outdated and quite large.  OCSP stapling embeds an OCSP response in the TLS Server Hello to remove the need for the client to contact the OCSP responder separately.  In order to work with OCSP you first need to create OCSP certificate and key pair in order to run an OCSP responder server with OpenSSL. Additionally you'll need a server or client key to verify.

Start by ensuring all certs are renewed:

```sh
rm -rf temp && make temp/ca.crt temp/ocsp.crt temp/client.p12 temp/server.crt
```

Now turn on the OCSP Responder server in another terminal instance:

```sh
make ocsp_responder
```

Verify the OCSP server information is on the client certificate with:

```sh
openssl x509 -in temp/client.crt -text -noout
```

A section that looks like this should appear:

```text
        X509v3 extensions:
            Authority Information Access:
                OCSP - URI:http://127.0.0.1:9999
```

Validate the client certificate with:

```sh
make ocsp_validate_client
```

You will see a response like:

```text
...
Response verify OK
temp/client.crt: unknown
        This Update: Sep 22 22:06:51 2020 GMT
        Next Update: Sep 22 22:11:51 2020 GMT
```

Validate the server certificate with:

```sh
make ocsp_validate_server
```

You will see a response like:

```text
...
Response verify OK
temp/server.crt: unknown
        This Update: Sep 22 22:06:51 2020 GMT
        Next Update: Sep 22 22:11:51 2020 GMT
```

Run the server now:

```sh
rm bin/iceberg && make bin/iceberg serve_example_ocsp
```

Get a file to show things are working and check that the OCSP responder was connected to:

```sh
make check_client_response
```

Check the OCSP response:

```sh
make ocsp_check_client_response
```

Now revoke the server:

```sh
make ocsp_revoke_server
```

Restart the responder and then validate the server certificate was revoked with:

```sh
make ocsp_validate_server
```

Check for output that has the `Revocation Time`:

```text
...
Response verify OK
temp/server.crt: revoked
        This Update: Sep 22 21:52:29 2020 GMT
        Next Update: Sep 22 21:57:29 2020 GMT
        Revocation Time: Sep 22 21:52:11 2020 GMT
```

And run again:

```sh
make check_client_response
```

Since the certificate was revoked, iceberg will not return the staple.  Check the response:

```sh
make ocsp_check_client_response
```

## Testing

**CLI**

To run CLI testes use `make test_cli`, which uses [shUnit2](https://github.com/kward/shunit2).  If you recive a `shunit2:FATAL Please declare TMPDIR with path on partition with exec permission.` error, you can modify the `TMPDIR` environment variable in line or with `export TMPDIR=<YOUR TEMP DIRECTORY HERE>`. For example:

```shell
TMPDIR="/usr/local/tmp" make test_cli
```

**Go**

To run Go tests use `make test_go` (or `bash scripts/test.sh`), which runs unit tests, `go vet`, `go vet with shadow`, [errcheck](https://github.com/kisielk/errcheck), [staticcheck](https://staticcheck.io/), and [misspell](https://github.com/client9/misspell).

## Contributing

We'd love to have your contributions!  Please see [CONTRIBUTING.md](CONTRIBUTING.md) for more info.

## Security

Please see [SECURITY.md](SECURITY.md) for more info.

## License

This project constitutes a work of the United States Government and is not subject to domestic copyright protection under 17 USC § 105.  However, because the project utilizes code licensed from contributors and other third parties, it therefore is licensed under the MIT License.  See LICENSE file for more information.
