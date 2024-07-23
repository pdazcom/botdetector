# SearchBot detector

SearchBot detector is a middleware plugin for [Traefik](https://github.com/traefik/traefik) which detect search engines scan-bots and verifies it by rDNS request. 
And then redirects/allows bots to one domain, and the rest to another.

## Configuration

### Static

```yaml
experimental:
  plugins:
    botdetector:
      modulename = "github.com/pdazcom/search-bots-detector"
      version = "v0.0.1"

entryPoints:
  http:
    address: ":80"
```

### Dynamic

To configure the `SearchBot detector` plugin you should create a [middleware](https://docs.traefik.io/middlewares/overview/) in your dynamic configuration as explained [here](https://docs.traefik.io/middlewares/overview/). The following example creates and uses the `botdetector` middleware plugin to redirect all search bots to the `bots.example.com` domain, and all others to `others.example.com`. In this case, redirection will only occur if the source host is not equal to the destination host.

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
        botsTo: 'bots.example.com'
        othersTo: 'others.example.com'
        botsList: # optional, check all search engines if empty. Allows only 'Google' and 'Yandex'
          - Google
          - Yandex
        permanent: false # if 'true' - redirect code = 301, 'false' - 302

  # Add the service
  services:
    service-foo:
      loadBalancer:
        servers:
        - url: http://localhost:5000/
        passHostHeader: false
```
