"""Hardened email-template rendering helpers.

Security model (user-supplied templates are display-only):

* Logic and presentation are separated: user templates may only contain
  text and ``{{ variable|filter }}`` expressions.  Statement tags
  (``{% ... %}`` — macros, includes, extends, blocks) are rejected, so
  user templates cannot define macros, pick layouts, or extend the
  inheritance chain.
* Attribute access is not exposed at all: any dunder (``__x__``) or
  dotted/attribute traversal is rejected, which closes the
  ``__class__.__mro__`` SSTI chain and the ``attr``/``getitem`` filter
  bypass.
* Filters are a whitelist (``SAFE_FILTERS``), not a blacklist — unknown
  filters, ``eval``-style filters, and encoding tricks are rejected.
* Output is auto-escaped by default; the explicit ``escape`` filter marks
  a value as already-safe instead of disabling escaping.
* Include paths are confined to a fixed root (no ``../`` traversal).
* Cache keys are namespaced per tenant so one tenant cannot poison
  another tenant's compiled-template cache.
* Rendering is bounded (template size + wall-clock timeout) and errors
  are sanitized — they never echo template source or context.
"""

import hashlib
import html
import os
import re
import time

# ---------------------------------------------------------------------------
# Whitelists and limits
# ---------------------------------------------------------------------------

#: Filters a user template may use.  Each maps a *string* to a *string*
#: (or a plain scalar); none of them touch objects, attributes, or code.
SAFE_FILTERS = {
    'upper': lambda v: str(v).upper(),
    'lower': lambda v: str(v).lower(),
    'title': lambda v: str(v).title(),
    'capitalize': lambda v: str(v).capitalize(),
    'strip': lambda v: str(v).strip(),
    'escape': lambda v: html.escape(str(v), quote=True),
    'e': lambda v: html.escape(str(v), quote=True),
    'length': lambda v: len(str(v)),
    'urlencode': lambda v: _urlencode(str(v)),
}

#: Filters that must never be reachable even if registered by accident.
#: (defense in depth on top of the whitelist)
DENIED_FILTERS = {'attr', 'getitem', 'eval', 'exec', 'import', 'format'}

#: Layout templates the system may select — users cannot override these.
ALLOWED_LAYOUTS = frozenset({'base.html', 'email.html', 'plain.html'})

#: Maximum template-inheritance depth for system templates.
MAX_INHERITANCE_DEPTH = 3

#: Maximum accepted template size (bytes) and render wall-clock (seconds).
MAX_TEMPLATE_SIZE = 64 * 1024
RENDER_TIMEOUT = 1.0

_VAR_RE = re.compile(r'\{\{(.*?)\}\}', re.DOTALL)
_NAME_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
_FILTER_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')

# Patterns that are never allowed in a user template.  Checked on the raw
# source so encodings/whitespace games inside expressions cannot slip by.
_DENIED_PATTERNS = (
    re.compile(r'__'),                 # dunder traversal (__class__, __mro__, ...)
    re.compile(r'<\s*script', re.I),   # injected script tag
    re.compile(r'\{%', re.I),          # statement tags: macro/include/extends/...
    re.compile(r'\b(eval|exec|__import__|compile|open|getattr|setattr|globals|locals|vars)\s*\('),
    re.compile(r'\b(attr|getitem)\b'), # Jinja object-traversal filters
    re.compile(r'\[.*\]'),             # subscript access
    re.compile(r'\.\s*[A-Za-z_]'),     # attribute access of any kind
)


class TemplateError(Exception):
    """Sanitized template error — never carries source or context data."""


def _urlencode(value):
    from urllib.parse import quote_plus
    return quote_plus(value)


def escape(value):
    """HTML-escape a value (encoding-normalized to str, quotes included)."""
    if value is None:
        return ''
    return html.escape(str(value), quote=True)


def check_template(template):
    """Statically validate a user template.  Returns True iff it is safe.

    Safe means: only literal text and ``{{ name|filter }}`` expressions
    with simple names and whitelisted filters; no statement tags, no
    attribute/subscript access, no dunder names, no script injection.
    """
    if not isinstance(template, str):
        return False
    if len(template) > MAX_TEMPLATE_SIZE:
        return False
    for pattern in _DENIED_PATTERNS:
        if pattern.search(template):
            return False
    for match in _VAR_RE.finditer(template):
        if not _check_expression(match.group(1)):
            return False
    return True


def _check_expression(expr):
    parts = [p.strip() for p in expr.split('|')]
    if not parts or not _NAME_RE.match(parts[0]):
        return False
    for filt in parts[1:]:
        # Filters take no arguments in user templates.
        if not _FILTER_RE.match(filt):
            return False
        if filt in DENIED_FILTERS or filt not in SAFE_FILTERS:
            return False
    return True


def render(template, context, allowed_filters, _timeout=RENDER_TIMEOUT):
    """Render a validated user template against a minimal context.

    ``context`` must be a plain dict of display values (callers must not
    pass connections or live objects); only simple names are resolved.
    ``allowed_filters`` further narrows SAFE_FILTERS for this render.
    Output is auto-escaped unless the expression ends in ``escape``/``e``.
    Raises TemplateError (sanitized) on any problem.
    """
    started = time.monotonic()
    if not isinstance(template, str) or len(template) > MAX_TEMPLATE_SIZE:
        raise TemplateError('template rejected')
    if not check_template(template):
        raise TemplateError('template rejected')
    context = context or {}
    allowed = set(allowed_filters or ()) & SAFE_FILTERS.keys()

    def _sub(match):
        if time.monotonic() - started > _timeout:
            raise TemplateError('render timeout')
        parts = [p.strip() for p in match.group(1).split('|')]
        name, filters = parts[0], parts[1:]
        value = context.get(name, '')
        if not isinstance(value, (str, int, float, bool, type(None))):
            # Context minimization: only plain display scalars are rendered.
            raise TemplateError('unsupported context value')
        escaped = False
        for filt in filters:
            if filt not in allowed:
                raise TemplateError('filter not allowed')
            value = SAFE_FILTERS[filt](value)
            if filt in ('escape', 'e'):
                escaped = True
        return str(value) if escaped else escape(value)

    try:
        return _VAR_RE.sub(_sub, template)
    except TemplateError:
        raise
    except Exception:
        # Error sanitization: no source, no context in the message.
        raise TemplateError('render failed') from None


def safe_include(path, root):
    """Resolve ``path`` inside ``root``; return None on traversal/escape."""
    if not path or not isinstance(path, str):
        return None
    if os.path.isabs(path) or '\x00' in path:
        return None
    root_real = os.path.realpath(root)
    candidate = os.path.realpath(os.path.join(root_real, path))
    if candidate != root_real and candidate.startswith(root_real + os.sep):
        return candidate
    return None


def cache_key(tenant, template):
    """Tenant-isolated cache key for a compiled template.

    Keyed on (tenant, template digest) so identical template text from
    different tenants never shares a cache entry.
    """
    tenant = '' if tenant is None else str(tenant)
    digest = hashlib.sha256(template.encode('utf-8')).hexdigest()
    return 'tpl:v1:{}:{}'.format(tenant, digest)
