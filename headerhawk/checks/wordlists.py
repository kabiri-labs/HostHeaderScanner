"""Header and virtual-host name lists exercised by the checks."""

# Headers commonly honoured by reverse proxies / frameworks for host routing.
HOST_HEADERS = [
    "Host",
    "X-Forwarded-Host",
    "X-Forwarded-For",
    "X-Forwarded-Server",
    "X-Host",
    "X-HTTP-Host-Override",
    "X-Original-Host",
    "X-Real-IP",
    "Forwarded",
    "X-Forwarded-Proto",
    "X-Forwarded-Scheme",
    "X-Forwarded-Port",
    "X-Forwarded-Prefix",
    "True-Client-IP",
    "CF-Connecting-IP",
    "Fastly-Client-IP",
    "X-Cluster-Client-IP",
    "Base-Url",
    "Request-Uri",
]

# Subset of headers that frameworks frequently treat as the effective host and
# that proxies often leave unkeyed in the cache (good cache-poisoning candidates).
UNKEYED_HOST_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-Original-Host",
    "X-HTTP-Host-Override",
    "Base-Url",
]

# Headers that may rewrite the routed path/ACL on the front-end (ACL bypass).
PATH_OVERRIDE_HEADERS = [
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Override-URL",
    "Request-Uri",
]

# Response headers that reveal whether a cache served the response.
CACHE_STATUS_HEADERS = [
    "X-Cache", "X-Cache-Hits", "Age", "CF-Cache-Status",
    "X-Served-By", "X-Cache-Lookup", "X-Drupal-Cache", "X-Varnish",
]

# Common internal/administrative virtual host names probed via the Host header.
DEFAULT_VHOST_WORDLIST = [
    "admin", "administrator", "internal", "intranet", "corp", "staging",
    "stage", "dev", "development", "test", "testing", "qa", "uat", "preprod",
    "beta", "api", "internal-api", "backend", "private", "jenkins", "gitlab",
    "jira", "confluence", "grafana", "kibana", "prometheus", "vault", "consul",
    "nexus", "sonar", "portal", "dashboard", "manage", "management", "console",
    "status", "metrics", "debug", "phpmyadmin", "adminer", "localhost",
    "gateway", "vpn", "mail",
]


# Header fields that a load balancer, reverse proxy, CDN or framework sets on
# the way in - the family ASVS 5.0 4.1.3 is about. These are the candidates for
# unkeyed-input discovery, and the choice is deliberate: a cache key is built
# from the method, host, path and query, so a header a *front-end* sets and a
# back-end honours is exactly the input that changes a response without
# changing where it is filed. Fuzzing arbitrary names would find far less and
# claim a requirement that does not cover it.
INTERMEDIARY_HEADERS = [
    # Host and scheme routing
    "X-Forwarded-Host", "X-Forwarded-Server", "X-Forwarded-Proto",
    "X-Forwarded-Scheme", "X-Forwarded-Port", "X-Forwarded-Prefix",
    "X-Forwarded-Path", "X-Forwarded-Ssl", "X-Forwarded-Protocol",
    "X-Host", "X-Original-Host", "X-HTTP-Host-Override", "X-Server-Name",
    "X-Original-Server", "Base-Url", "X-Base-Url", "X-Backend-Host",
    "X-Real-Host", "X-Proxy-Host", "X-Frontend-Host", "Front-End-Https",
    "X-Forwarded", "Forwarded", "X-ProxyUser-Ip",
    # Path and URL rewriting
    "X-Original-URL", "X-Rewrite-URL", "X-Override-URL", "X-Originating-URL",
    "Request-Uri", "X-Request-Uri", "X-Original-Path", "X-Envoy-Original-Path",
    # Client identity, which applications routinely branch on
    "X-Real-IP", "X-Client-IP", "X-Cluster-Client-IP", "True-Client-IP",
    "CF-Connecting-IP", "Fastly-Client-IP", "Fly-Client-IP", "X-Azure-ClientIP",
    "X-Coming-From", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
    "X-Client-Host", "Client-IP", "X-Forwarded-For-Original",
    # CDN and edge hints
    "CF-IPCountry", "CF-Visitor", "CDN-Loop", "Fastly-SSL", "Fastly-FF",
    "X-Akamai-Edgescape", "Akamai-Origin-Hop", "X-Edge-IP", "X-Cache-Key",
    "X-Cdn", "X-Vercel-IP-Country", "X-Amz-Cf-Id", "X-Amzn-Trace-Id",
    "X-Azure-Ref", "Surrogate-Capability",
    # Framework and gateway conventions
    "X-Envoy-External-Address", "X-Envoy-Internal", "X-Traefik-Router",
    "X-Nginx-Proxy", "X-Varnish", "X-Middleware-Prefetch",
    "X-Api-Version", "X-Wap-Profile", "X-ATT-DeviceId", "X-UIDH",
    "X-Device-Type", "X-Is-Mobile", "X-Country-Code", "X-Locale",
    "X-Timezone", "X-Tenant-Id", "X-Organization-Id", "X-Account-Id",
    # Protocol and negotiation hints a back-end may echo
    "X-HTTP-Method-Override", "X-Method-Override", "X-Accept-Version",
    "X-Purpose", "X-Moz", "Sec-Purpose", "Save-Data", "Viewport-Width",
    "X-Requested-With", "X-Prototype-Version", "X-CSRF-Token",
]
