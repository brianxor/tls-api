# TlsApi

A wrapper for [tls-client](https://github.com/bogdanfinn/tls-client) library.

## Description

An API that forwards your http requests using a custom TLS fingerprint.

## Installation

1. `git clone https://github.com/brianxor/tls-api.git`
2. `cd tls-api`
3. `go run .`

> [!NOTE]
> Configure the API server host and port through `.env` file.

## Documentation

Endpoint: `/tls/handle`

Method: `POST`

Headers:
```
x-tls-url
x-tls-method
x-tls-proxy
x-tls-profile
x-tls-client-timeout
x-tls-follow-redirects
x-tls-with-random-extension-order
x-tls-header-order
x-tls-pseudo-header-order
```

### x-tls-url

- Request URL

Required: `true`

### x-tls-method

- Request Method

Required: `true`

### x-tls-proxy

- Proxy

Required: `false`

You can enter the proxy in the following formats:

- `ip:port:user:pass`
- `ip:port`

Proxy will be formatted automatically.

### x-tls-profile

Required: `true`

Type: `string`

See [profiles](https://github.com/bogdanfinn/tls-client/blob/18abae60034c6d510a17b62c936efafdf53ebb80/profiles/profiles.go#L10) for a list of available TLS profiles.

### x-tls-client-timeout

Request Timeout

- Required: `true`
- Default: `30`

### x-tls-follow-redirects

Request Follow Redirects

- Required: `true`
- Default: `true`

### x-tls-with-random-extension-order

Random TLS Extension Order

- Required: `true`
- Default: `true`

### x-tls-header-order

TLS Header Keys Order

- Required: `true`

They must be provided as a string, all separate by a comma (`,`).

### x-tls-pseudo-header-order

TLS Pseudo Header Keys Order

- Required: `true`

They must be provided as a string, all separate by a comma (`,`).

## Credits

Credits to [bogdanfinn](https://github.com/bogdanfinn/) for making the awesome [tls-client](https://github.com/bogdanfinn/tls-client).