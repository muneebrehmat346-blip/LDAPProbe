"""Detects directory-server error text in a response body.

Step 5 of the build plan. These are common strings that leak from
LDAP bindings and directory servers when a malformed filter reaches
them -- not proof of exploitation by themselves, but strong evidence
when combined with the comparator's findings.
"""

DIRECTORY_ERROR_PATTERNS = [
    "ldapexception",
    "javax.naming",
    "invalid dn syntax",
    "ldap: error code",
    "bad search filter",
    "size limit exceeded",
    "python-ldap",
    "ldap.filter",
    "unbalanced parenthesis",
    "com.novell.ldap",
]


def find_directory_error(body):
    """Return the matched pattern if body contains directory error text, else None.

    Matching is case-insensitive and substring-based, since these
    error strings show up embedded in stack traces or JSON error
    fields with varying surrounding text.
    """
    lower_body = body.lower()
    for pattern in DIRECTORY_ERROR_PATTERNS:
        if pattern in lower_body:
            return pattern
    return None
