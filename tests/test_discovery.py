"""Tests for endpoint discovery, shape collapsing and check scope.

Two things decide whether discovery is usable rather than merely present. URLs
that are the same endpoint must collapse, or a paginated site spends the whole
budget on one route. And checks whose weakness belongs to the host must not be
repeated per endpoint, or the scan does several times the work to file several
copies of the same finding.
"""

import json
import unittest
from unittest import mock

import requests

import headerhawk as hhs
from headerhawk.core.scope import SCOPE_ENDPOINT, SCOPE_HOST, runs_on
from headerhawk.discovery import discover
from headerhawk.discovery.shape import (deduplicate, endpoint_shape,
                                        segment_shape)
from headerhawk.discovery.sources import (from_links, from_openapi,
                                          from_robots, from_sitemap,
                                          same_origin)
from tests.helpers import FakeResponse

BASE = "http://t.example"


class _Site:
    """Session double serving a fixed map of path -> body."""

    def __init__(self, pages):
        self.verify = True
        self.headers = {}
        self.proxies = {}
        self.requested = []
        self._pages = pages

    def request(self, method, url=None, timeout=None, allow_redirects=True,
                **kwargs):
        self.requested.append(url)
        path = url[len(BASE):] if url.startswith(BASE) else url
        if path not in self._pages:
            return FakeResponse(404, text="", url=url)
        return FakeResponse(200, text=self._pages[path], url=url)


class SegmentShapeTests(unittest.TestCase):
    def test_numeric_segments_collapse(self):
        self.assertEqual(segment_shape("1041"), "{n}")

    def test_uuids_collapse(self):
        self.assertEqual(
            segment_shape("3f2504e0-4f89-11d3-9a0c-0305e82c3301"), "{id}")

    def test_long_hex_collapses(self):
        self.assertEqual(segment_shape("a1b2c3d4e5f6a7b8"), "{id}")

    def test_a_long_mixed_slug_collapses(self):
        self.assertEqual(segment_shape("post-2024-abc123def"), "{id}")

    def test_ordinary_words_are_kept(self):
        for word in ("pricing", "admin", "users", "api", "v2", "health"):
            self.assertEqual(segment_shape(word), word, word)


class EndpointShapeTests(unittest.TestCase):
    def test_the_same_route_with_different_ids_is_one_endpoint(self):
        self.assertEqual(endpoint_shape(f"{BASE}/order/1041"),
                         endpoint_shape(f"{BASE}/order/1042"))

    def test_different_routes_stay_different(self):
        self.assertNotEqual(endpoint_shape(f"{BASE}/order/1"),
                            endpoint_shape(f"{BASE}/invoice/1"))

    def test_a_query_reduces_to_its_parameter_names(self):
        self.assertEqual(endpoint_shape(f"{BASE}/search?q=hats"),
                         endpoint_shape(f"{BASE}/search?q=shoes"))

    def test_different_parameters_are_different_endpoints(self):
        self.assertNotEqual(endpoint_shape(f"{BASE}/search?q=x"),
                            endpoint_shape(f"{BASE}/search?category=x"))

    def test_the_same_path_on_two_hosts_stays_two_endpoints(self):
        self.assertNotEqual(endpoint_shape("http://a.example/x"),
                            endpoint_shape("http://b.example/x"))

    def test_deduplicate_keeps_the_first_of_each_shape(self):
        kept = deduplicate([f"{BASE}/order/1", f"{BASE}/order/2",
                            f"{BASE}/pricing", f"{BASE}/order/3"])
        self.assertEqual(kept, [f"{BASE}/order/1", f"{BASE}/pricing"])


class SameOriginTests(unittest.TestCase):
    def test_the_same_origin_is_accepted(self):
        self.assertTrue(same_origin(f"{BASE}/x", BASE))

    def test_another_host_is_rejected(self):
        self.assertFalse(same_origin("http://other.example/x", BASE))

    def test_another_scheme_is_rejected(self):
        self.assertFalse(same_origin("https://t.example/x", BASE))

    def test_non_http_schemes_are_rejected(self):
        self.assertFalse(same_origin("mailto:a@b.c", BASE))


class RobotsTests(unittest.TestCase):
    def test_named_paths_and_sitemaps_are_taken(self):
        site = _Site({"/robots.txt":
                      f"User-agent: *\nDisallow: /admin\nAllow: /public\n"
                      f"Sitemap: {BASE}/sm.xml\n"})
        urls, sitemaps = from_robots(site, BASE, 1)
        self.assertIn(f"{BASE}/admin", urls)
        self.assertIn(f"{BASE}/public", urls)
        self.assertEqual(sitemaps, [f"{BASE}/sm.xml"])

    def test_a_wildcard_path_is_trimmed_at_the_star(self):
        site = _Site({"/robots.txt": "Disallow: /private/*.json\n"})
        urls, _ = from_robots(site, BASE, 1)
        self.assertEqual(urls, [f"{BASE}/private/"])

    def test_a_missing_robots_file_yields_nothing(self):
        self.assertEqual(from_robots(_Site({}), BASE, 1), ([], []))


class SitemapTests(unittest.TestCase):
    def test_locations_are_taken(self):
        site = _Site({"/sitemap.xml":
                      f"<urlset><url><loc>{BASE}/a</loc></url>"
                      f"<url><loc>{BASE}/b</loc></url></urlset>"})
        self.assertEqual(from_sitemap(site, BASE, 1), [f"{BASE}/a", f"{BASE}/b"])

    def test_a_sitemap_index_is_followed_one_level(self):
        site = _Site({
            "/sitemap.xml": f"<sitemapindex><sitemap><loc>{BASE}/s1.xml</loc>"
                            f"</sitemap></sitemapindex>",
            "/s1.xml": f"<urlset><url><loc>{BASE}/deep</loc></url></urlset>",
        })
        self.assertEqual(from_sitemap(site, BASE, 1), [f"{BASE}/deep"])

    def test_other_origins_in_a_sitemap_are_dropped(self):
        site = _Site({"/sitemap.xml":
                      f"<urlset><url><loc>{BASE}/ok</loc></url>"
                      f"<url><loc>http://elsewhere.example/no</loc></url></urlset>"})
        self.assertEqual(from_sitemap(site, BASE, 1), [f"{BASE}/ok"])

    def test_a_missing_sitemap_yields_nothing(self):
        self.assertEqual(from_sitemap(_Site({}), BASE, 1), [])


class OpenApiTests(unittest.TestCase):
    def _site(self, spec, path="/openapi.json"):
        return _Site({path: json.dumps(spec)})

    def test_paths_become_urls(self):
        site = self._site({"paths": {"/users": {}, "/health": {}}})
        urls = from_openapi(site, BASE, 1)
        self.assertIn(f"{BASE}/users", urls)
        self.assertIn(f"{BASE}/health", urls)

    def test_a_server_prefix_is_applied(self):
        site = self._site({"servers": [{"url": f"{BASE}/api"}],
                           "paths": {"/users": {}}})
        self.assertEqual(from_openapi(site, BASE, 1), [f"{BASE}/api/users"])

    def test_a_swagger_base_path_is_applied(self):
        site = self._site({"basePath": "/v1", "paths": {"/users": {}}})
        self.assertEqual(from_openapi(site, BASE, 1), [f"{BASE}/v1/users"])

    def test_path_parameters_are_filled_in(self):
        # Requesting the template verbatim asks for a path that percent-encodes
        # to %7Bid%7D and exists nowhere.
        site = self._site({"paths": {"/users/{id}": {}}})
        self.assertEqual(from_openapi(site, BASE, 1), [f"{BASE}/users/1"])

    def test_an_explicit_url_is_used_when_given(self):
        site = _Site({"/custom/spec.json": json.dumps({"paths": {"/x": {}}})})
        urls = from_openapi(site, BASE, 1,
                            explicit_url=f"{BASE}/custom/spec.json")
        self.assertEqual(urls, [f"{BASE}/x"])

    def test_malformed_json_yields_nothing(self):
        self.assertEqual(from_openapi(_Site({"/openapi.json": "{nope"}),
                                      BASE, 1), [])

    def test_no_spec_yields_nothing(self):
        self.assertEqual(from_openapi(_Site({}), BASE, 1), [])


class LinkTests(unittest.TestCase):
    def test_same_origin_links_are_taken(self):
        site = _Site({"/": '<a href="/contact">c</a><a href="/about">a</a>'})
        urls = from_links(site, BASE + "/", 1)
        self.assertIn(f"{BASE}/contact", urls)

    def test_other_origins_and_schemes_are_skipped(self):
        site = _Site({"/": '<a href="mailto:a@b.c">m</a>'
                           '<a href="javascript:x()">j</a>'
                           '<a href="http://elsewhere.example/x">e</a>'
                           '<a href="/kept">k</a>'})
        self.assertEqual(from_links(site, BASE + "/", 1), [f"{BASE}/kept"])

    def test_fragments_are_stripped(self):
        site = _Site({"/": '<a href="/page#section">p</a>'})
        self.assertEqual(from_links(site, BASE + "/", 1), [f"{BASE}/page"])

    def test_an_unreachable_page_yields_nothing(self):
        broken = _Site({})
        broken.request = lambda *a, **k: (_ for _ in ()).throw(
            requests.ConnectionError("nope"))
        self.assertEqual(from_links(broken, BASE + "/", 1), [])


class DiscoverTests(unittest.TestCase):
    def _site(self):
        return _Site({
            "/robots.txt": f"Disallow: /admin\nSitemap: {BASE}/sitemap.xml\n",
            "/sitemap.xml": f"<urlset><url><loc>{BASE}/order/1</loc></url>"
                            f"<url><loc>{BASE}/order/2</loc></url>"
                            f"<url><loc>{BASE}/pricing</loc></url></urlset>",
            "/openapi.json": json.dumps({"paths": {"/api/health": {}}}),
            "/": '<a href="/contact">c</a>',
        })

    def test_the_requested_target_always_comes_first(self):
        found = discover(self._site(), BASE + "/", 1)
        self.assertEqual(found.urls[0], BASE + "/")

    def test_every_source_contributes(self):
        found = discover(self._site(), BASE + "/", 1)
        self.assertEqual(set(found.sources),
                         {"OpenAPI", "sitemap", "robots.txt", "links"})

    def test_repeated_shapes_take_one_slot(self):
        found = discover(self._site(), BASE + "/", 1)
        orders = [url for url in found.urls if "/order/" in url]
        self.assertEqual(len(orders), 1)

    def test_the_limit_is_applied_and_the_remainder_reported(self):
        found = discover(self._site(), BASE + "/", 1, limit=2)
        self.assertEqual(len(found.urls), 2)
        self.assertGreater(found.considered, 2)

    def test_the_target_survives_a_limit_of_one(self):
        found = discover(self._site(), BASE + "/", 1, limit=1)
        self.assertEqual(found.urls, [BASE + "/"])

    def test_a_silent_target_still_yields_the_target(self):
        found = discover(_Site({}), BASE + "/", 1)
        self.assertEqual(found.urls, [BASE + "/"])
        self.assertEqual(found.sources, [])


class ScopeTests(unittest.TestCase):
    def test_host_level_checks_run_only_on_the_requested_target(self):
        for check in hhs.CHECKS:
            if check.scope == SCOPE_HOST:
                self.assertTrue(runs_on(check, True), check.__name__)
                self.assertFalse(runs_on(check, False), check.__name__)

    def test_endpoint_level_checks_run_everywhere(self):
        for check in hhs.CHECKS:
            if check.scope == SCOPE_ENDPOINT:
                self.assertTrue(runs_on(check, True), check.__name__)
                self.assertTrue(runs_on(check, False), check.__name__)

    def test_the_expensive_host_checks_are_host_scoped(self):
        # These issue the bulk of a scan's requests and their weakness belongs
        # to the front-end, so repeating them per route is pure waste.
        host_scoped = {c.test_type for c in hhs.CHECKS if c.scope == SCOPE_HOST}
        self.assertEqual(host_scoped,
                         {"Virtual Host Discovery", "Host Header Bypass",
                          "SSRF", "HTTP Request Smuggling"})

    def test_posture_is_endpoint_scoped(self):
        # Header posture varies by route; that is the whole reason to discover.
        self.assertEqual(hhs.ResponseHeaderPostureTest.scope, SCOPE_ENDPOINT)


class CliTests(unittest.TestCase):
    def _args(self, *extra):
        with mock.patch("sys.argv", ["prog", "http://t/", *extra]):
            return hhs.parse_arguments()

    def test_discovery_is_off_by_default(self):
        self.assertFalse(self._args().discover)

    def test_the_limit_has_a_default(self):
        self.assertGreaterEqual(self._args().max_endpoints, 1)

    def test_a_zero_limit_is_rejected(self):
        with self.assertRaises(SystemExit):
            self._args("--discover", "--max-endpoints", "0")

    def test_openapi_without_discover_is_rejected(self):
        # It would silently do nothing otherwise.
        with self.assertRaises(SystemExit):
            self._args("--openapi", "http://t/spec.json")

    def test_openapi_with_discover_is_accepted(self):
        args = self._args("--discover", "--openapi", "http://t/spec.json")
        self.assertEqual(args.openapi, "http://t/spec.json")


if __name__ == "__main__":
    unittest.main()
