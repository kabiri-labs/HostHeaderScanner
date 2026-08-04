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
