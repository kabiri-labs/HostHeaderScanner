"""Which controls each class of finding demonstrates a failure of.

A finding is mapped only where the control genuinely covers it. Several finding
types have no entry, and that is deliberate: reports say so explicitly rather
than stretching a nearby requirement to fill the column.
"""

from .catalogue import CONTROLS

CONTROLS_BY_TEST = {
    # Injecting a routing header the front-end trusts is exactly the override
    # 4.1.3 requires to be impossible.
    "Host Header Injection": ("ASVS-5.0:4.1.3",),
    "Host Header Bypass": ("ASVS-5.0:4.1.3",),
    "Web Cache Poisoning": ("ASVS-5.0:4.1.3",),
    # A bypass driven by a client-supplied header is both an override of an
    # intermediary's header and an authorization decision made on data the
    # consumer controls.
    "Auth Bypass": ("ASVS-5.0:4.1.3", "ASVS-5.0:8.3.1"),
    "Virtual Host Discovery": ("ASVS-5.0:13.4.5",),
    "SSRF": ("ASVS-5.0:13.2.4", "ASVS-5.0:13.2.5"),
    "URL Parameter SSRF": ("ASVS-5.0:13.2.4", "ASVS-5.0:13.2.5"),
    "Blind SSRF (OOB)": ("ASVS-5.0:13.2.4", "ASVS-5.0:13.2.5"),
    "Open Redirect": ("ASVS-5.0:3.7.2",),
    # Response-header posture.
    "Strict-Transport-Security": ("ASVS-5.0:3.4.1",),
    "Content-Security-Policy": ("ASVS-5.0:3.4.3",),
    "X-Content-Type-Options": ("ASVS-5.0:3.4.4",),
    "Referrer-Policy": ("ASVS-5.0:3.4.5",),
    "Frame Protection": ("ASVS-5.0:3.4.6",),
    "Cross-Origin-Opener-Policy": ("ASVS-5.0:3.4.8",),
    "Version Disclosure": ("ASVS-5.0:13.4.6",),
    # 3.4.3 is what makes a policy meaningful, so the deeper script-source
    # analysis verifies the same requirement as the policy's presence.
    "CSP Script Sources": ("ASVS-5.0:3.4.3",),
    "CSP Violation Reporting": ("ASVS-5.0:3.4.7",),
    # Cookie attributes.
    "Cookie HttpOnly Attribute": ("ASVS-5.0:3.3.4",),
    "Cookie Secure Attribute": ("ASVS-5.0:3.3.1",),
    "Cookie SameSite Attribute": ("ASVS-5.0:3.3.2",),
    "Cookie Name Prefix": ("ASVS-5.0:3.3.1", "ASVS-5.0:3.3.3"),
    "Cookie Size": ("ASVS-5.0:3.3.5",),
    # ASVS 5.0 has no Permissions-Policy requirement, so this stays unmapped
    # rather than borrowing a neighbouring one.
    "Permissions-Policy": (),
}

# A mapping that points at an id no longer in the catalogue would render as a
# bare string in reports and quietly lose its citation, so refuse to import.
_UNKNOWN = {control_id
            for control_ids in CONTROLS_BY_TEST.values()
            for control_id in control_ids
            if control_id not in CONTROLS}
if _UNKNOWN:
    raise ImportError(
        f"compliance mapping references uncatalogued control(s): "
        f"{', '.join(sorted(_UNKNOWN))}")


def controls_for(test_type):
    """Return the control ids a finding type maps onto (empty when unmapped)."""
    return CONTROLS_BY_TEST.get(test_type, ())
