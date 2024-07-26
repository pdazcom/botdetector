# SearchBot detector

![Go Version](https://img.shields.io/github/go-mod/go-version/pdazcom/botdetector?style=flat-square)
![Latest Release](https://img.shields.io/github/release/pdazcom/botdetector/all.svg?style=flat-square)

SearchBot detector is a middleware plugin for [Traefik](https://github.com/traefik/traefik) which detect search engines scan-bots and verifies it by rDNS request. 
And then redirects/allows bots to one domain, and the rest to another.

## How it works

This is a simple plugin that detects search bots by the `User-Agent` header and also verifies them via an rDNS request. 

This way, no scanners will be able to pretend to be search bots from Google, Yandex, etc.

After all checks, the bots are redirected to the domain for bots (option `botsTo`), the rest to the other (option `othersTo`). 
The `X-SearchBot-Detected` header is also added with the value from the `botTag` option (default "true")

The `X-SearchBot-Detected` header can also be used as an exception to the rules. Set the value of the `botTag` parameter as a password so that no one can guess it. Add this header and your requests will be identified as “search bots” without additional checks.

## Configuration

### Static

```yaml
experimental:
  plugins:
    botdetector:
      modulename = "github.com/pdazcom/botdetector"
      version = "v0.1.1"

entryPoints:
  http:
    address: ":80"
```

### Dynamic

To configure the `SearchBot detector` plugin you should create a [middleware](https://docs.traefik.io/middlewares/overview/) in your dynamic configuration as explained [here](https://docs.traefik.io/middlewares/overview/).

This plugin supports these configuration (all of them optional):

* `botsTo`: host to redirect **bots** requests if source host is different.
* `othersTo`: host to redirect **others** requests if source host is different.
* `botsList`: list of search engine bots that need to be checked. Checks all if empty.
* `permanent`: sets the redirect type: 'true' - redirect code = 301, 'false' - 302. Default: false.
* `botTag`: header `X-SearchBot-Detected` value to mark search bots requests. Default: "true"

**Note**: Leave `botsTo` and `othersTo` empty to only mark bot requests with the `X-SearchBot-Detected` header without redirects.

The following example creates and uses the `botdetector` middleware plugin to redirect all search bots to the `bots.example.com` domain, and all others to `others.example.com`. In this case, redirection will only occur if the source host is not equal to the destination host.

#### Example

```yaml
http:
  # Add the router
  routers:
    my-router:
      entryPoints:
        - http
      middlewares:
        - botdetector
      service: service-foo
      rule: Host(`bots.example.com`) || Host(`others.example.com`)

  # Add the middleware
  middlewares:
    botdetector:
      plugin:
        botsTo: "bots.example.com"      # host to redirect bots requests
        othersTo: "others.example.com"  # host to redirect others requests
        botsList:                       # allows only 'Google' and 'Yandex'
          - Google
          - Yandex
        permanent: false                # if 'true' - redirect code = 301, 'false' - 302. Default: false
        botTag: "this-is-bot"           # header 'X-SearchBot-Detected' value to mark search bots requests. Default: "true"

  # Add the service
  services:
    service-foo:
      loadBalancer:
        servers:
        - url: http://localhost:5000/
        passHostHeader: false
```

## Security

If you discover any security related issues, please email `kostya.dn@gmail.com` instead of using the issue tracker.

## Credits

- [Konstantin A.][link-author]
- [All Contributors][link-contributors]


[link-author]: https://github.com/pdazcom
[link-contributors]: ../../contributors
