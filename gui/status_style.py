"""Status colors used by the desktop results tables (foreground, background)."""


def status_colors(status: int):
    """Return readable foreground/background hex colors for an HTTP response."""
    try:
        code = int(status)
    except (TypeError, ValueError):
        return "#202124", "#ffffff"

    if 200 <= code < 300:
        return "#1b5e20", "#e8f5e9"
    if 300 <= code < 400:
        return "#795500", "#fff8e1"
    if code in (401, 403) or 500 <= code < 600:
        return "#b71c1c", "#ffebee"
    if code == 404 or code in (400, 410):
        return "#455a64", "#eceff1"
    if code == 429:
        return "#6a1b9a", "#f3e5f5"
    return "#202124", "#ffffff"
