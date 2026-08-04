"""Out-of-band interaction management and confirmation."""

import time
import uuid

import requests
from colorama import Fore, Style

from ..compliance import controls_for
from .findings import CLASS_VULNERABILITY
from .severity import severity_for

OOB_TEST_TYPE = "Blind SSRF (OOB)"


class OOBManager:
    """Out-of-band interaction manager.

    Embeds a per-scan correlation id into OOB payload hostnames and, when a
    listener export URL is supplied (``--oob-poll-url``), polls it afterwards to
    confirm blind interactions. Works with any listener whose export endpoint
    returns the received hostnames in its body: interactsh (``-json``),
    webhook.site, RequestBin, Burp Collaborator exports, custom sinks, etc.
    """

    def __init__(self, oob_domain, poll_url=None):
        self.oob_domain = oob_domain.strip("/").lstrip(".")
        self.poll_url = poll_url
        self.scan_id = uuid.uuid4().hex[:8]
        self.labels = {}

    def host(self, label):
        host = f"{label}-{self.scan_id}.{self.oob_domain}"
        self.labels[label] = host
        return host

    def url(self, label):
        return f"http://{self.host(label)}/"

    def poll(self, session, timeout, attempts=4, delay=3):
        if not self.poll_url:
            return []
        for attempt in range(attempts):
            body = ""
            try:
                body = session.get(self.poll_url, timeout=timeout).text or ""
            except requests.RequestException:
                pass
            hits = [label for label, host in self.labels.items()
                    if host in body or self.scan_id in body]
            if hits:
                return hits
            if attempt < attempts - 1:
                time.sleep(delay)
        return []

def confirm_oob_interactions(oob_manager, session, timeout, tests):
    """Poll the OOB listener and record any confirmed blind interactions."""
    hits = oob_manager.poll(session, timeout)
    if not hits:
        print(Fore.GREEN + "No OOB interactions recorded.")
        return
    by_type = {test.test_type: test for test in tests}
    label_to_type = {
        "ssrf": "SSRF",
        "host": "Host Header Injection",
        "param": "URL Parameter SSRF",
        "redirect": "Open Redirect",
    }
    for label in hits:
        owner = by_type.get(label_to_type.get(label, ""), tests[0])
        owner.vulnerabilities_found.append({
            "test_type": OOB_TEST_TYPE,
            "test_result": "Vulnerable",
            "severity": severity_for(OOB_TEST_TYPE),
            "controls": list(controls_for(OOB_TEST_TYPE)),
            "finding_class": CLASS_VULNERABILITY,
            "url": owner.target_url,
            "method": "GET",
            "header_name": label,
            "payload": oob_manager.labels.get(label, ""),
            "status_code": "N/A",
            "analysis": (
                f"Out-of-band interaction received from the '{label}' payload "
                f"(scan id {oob_manager.scan_id}); confirms blind SSRF."
            ),
            "repro": "",
        })
        print(Fore.RED + Style.BRIGHT +
              f"[!] OOB interaction confirmed for '{label}' payload -> blind SSRF.")
