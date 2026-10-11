from gui.status_style import status_colors


def test_success_status_uses_green_row_colors():
    fg, bg = status_colors(200)
    assert fg == "#1b5e20"
    assert bg == "#e8f5e9"


def test_redirect_and_error_statuses_are_distinguishable():
    assert status_colors(302) != status_colors(403)
    assert status_colors(403) != status_colors(404)
    assert status_colors(429) != status_colors(404)
    assert status_colors(503) == status_colors(403)


def test_unknown_status_has_safe_fallback():
    assert status_colors(0) == ("#202124", "#ffffff")
