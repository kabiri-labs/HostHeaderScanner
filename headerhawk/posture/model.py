"""The shapes a posture rule works with.

Kept in their own module so the cookie rules and the header rules can both use
them without importing each other.
"""

from collections import namedtuple

# One problem found by a rule. ``subject`` names what the finding is about - a
# header field for most rules, an individual cookie for the cookie rules - and
# becomes the finding's header_name, so two cookies failing the same rule stay
# distinguishable in a report and get separate fingerprints.
Issue = namedtuple("Issue", "test_result analysis subject")

# ``assess`` takes a ResponseFacts and returns a list of Issue (empty when the
# control is in place).
PostureRule = namedtuple("PostureRule", "test_type severity assess")
