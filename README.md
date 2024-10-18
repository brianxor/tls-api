# 🔒 TlsApi

A wrapper for [tls-client](https://github.com/bogdanfinn/tls-client) library.

## 📝 Description

An API that forwards your HTTP requests using a custom TLS fingerprint.

## 🚀 Installation

1. `git clone https://github.com/brianxor/tls-api.git`
2. `cd tls-api`
3. `go run .`

> [!TIP]
> Configure the API server host and port through `.env` file.

## 📚 Documentation

### Endpoint: `/tls/forward`

### Method: `POST`

### Headers:

| Header                              | Description                   |
|-------------------------------------|-------------------------------|
| `x-tls-url`                         | 🌐 Request URL                |
| `x-tls-method`                      | 📮 Request method             |
| `x-tls-proxy`                       | 🔄 Proxy settings             |
| `x-tls-profile`                     | 👤 TLS client profile         |
| `x-tls-client-timeout`              | ⏱️ HTTP client timeout        |
| `x-tls-follow-redirects`            | 🔀 Follow redirects           |
| `x-tls-force-http1`                 | 🔌 Force HTTP1                |
| `x-tls-insecure-skip-verify`        | 🚫 Skip SSL verification      |
| `x-tls-with-random-extension-order` | 🎲 Randomize extensions order |
| `x-tls-header-order`                | 📋 Header order               |
| `x-tls-pseudo-header-order`         | 📑 Pseudo header order        |

> [!NOTE]
> If the request requires a body, you can simply enter it as the request body, not in header.

### Detailed Header Descriptions

#### x-tls-url
- 🔍 Configures the request URL
- Optional: `false`

#### x-tls-method
- 🛠️ Configures the request method
- Optional: `false`

#### x-tls-proxy
- 🔒 Configures the proxy for the request
- Optional: `true`
- Formats:
    - `ip:port:user:pass`
    - `ip:port`

#### x-tls-profile
- 👥 Configures the TLS client profile
- Optional: `false`
- Type: `string`
- Available profiles: [See here](https://github.com/bogdanfinn/tls-client/blob/18abae60034c6d510a17b62c936efafdf53ebb80/profiles/profiles.go#L10)

#### x-tls-client-timeout
- ⏳ Configures the HTTP client timeout
- Optional: `true`
- Default: `30`

#### x-tls-follow-redirects
- 🔗 Configures if the request should follow redirects
- Optional: `true`
- Default: `true`

#### x-tls-force-http1
- 🔒 Configures if the request should force HTTP1 use
- Optional: `true`
- Default: `false`

#### x-tls-insecure-skip-verify
- 🚫 Configures if the client should skip SSL certificate verification
- Optional: `true`
- Default: `false`

#### x-tls-with-random-extension-order
- 🔀 Configures if the client should randomize extensions order
- Optional: `true`
- Default: `true`

#### x-tls-header-order
- 📊 Configures the header order of the request
- Optional: `false`
- Format: String with headers key separated by commas (`,`)

#### x-tls-pseudo-header-order
- 📈 Configures the pseudo header order of the request
- Optional: `false`
- Format: String with headers key separated by commas (`,`)

## 🐛 Report Issues

Found a bug? Please [open an issue](https://github.com/brianxor/tls-api/issues).

By reporting an issue you help improving the project.

## 🙏 Credits

Special thanks to [bogdanfinn](https://github.com/bogdanfinn/) for creating the awesome [tls-client](https://github.com/bogdanfinn/tls-client) library.

