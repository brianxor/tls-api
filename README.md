# TlsApi

A wrapper for [tls-client](https://github.com/bogdanfinn/tls-client) library.

## Description

An API that forwards your http requests using a custom TLS fingerprint.

## Installation

1. `git clone https://github.com/brianxor/tls-api.git`
2. `cd tls-api`
3. `go run .`

> [!TIP]
> Configure the API server host and port through `.env` file.

## Documentation

Endpoint: `/tls/forward`

Method: `POST`

Headers:
```
x-tls-url
x-tls-method
x-tls-proxy
x-tls-profile
x-tls-client-timeout
x-tls-follow-redirects
x-tls-force-http1
x-tls-with-random-extension-order
x-tls-header-order
x-tls-pseudo-header-order
```

If the request requires a body, you can simply enter it as the request body, not in header.

### x-tls-url

- This header will configure what request url the request is going to use.

Required: `true`

### x-tls-method

- This header will configure what request method the request is going to use

Required: `true`

### x-tls-proxy

- This header will configure what proxy the request is going to use. 

Required: `false`

You can enter the proxy in the following formats:

- `ip:port:user:pass`
- `ip:port`

Proxy will be formatted automatically.

### x-tls-profile

This header will configure what TLS client profile the request is going to use.

Required: `true`

Type: `string`

See [profiles](https://github.com/bogdanfinn/tls-client/blob/18abae60034c6d510a17b62c936efafdf53ebb80/profiles/profiles.go#L10) for a list of available TLS profiles.

### x-tls-client-timeout

This header will configure what timeout the HTTP client is going to use.

- Required: `true`
- Default: `30`

### x-tls-follow-redirects

This header will configure if the request should follow redirects or not.

- Required: `true`
- Default: `true`

### x-tls-force-http1

This header will configure if the request should force HTTP1 use or not.

- Required: `true`
- Default: `false`


### x-tls-with-random-extension-order

This header will configure if the client should randomize extensions order.

- Required: `true`
- Default: `true`

### x-tls-header-order

This header will configure the header order of the request.

- Required: `true`

They must be provided as a string, all separated by a comma (`,`).

### x-tls-pseudo-header-order

This header will configure the pseudo header order of the request.

- Required: `true`

They must be provided as a string, all separated by a comma (`,`).

## Credits

Credits to [bogdanfinn](https://github.com/bogdanfinn/) for making the awesome [tls-client](https://github.com/bogdanfinn/tls-client).