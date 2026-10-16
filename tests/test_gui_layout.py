"""Offscreen smoke tests for the application's collapsible workspace controls."""
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def test_scan_settings_filters_panels_and_columns_can_be_toggled():
    try:
        from PySide6.QtWidgets import QApplication
        from gui.main_window import MainWindow
    except (ImportError, OSError) as exc:
        # Some minimal Ubuntu runners omit Qt's system EGL library. The Windows CI
        # job exercises this GUI smoke test with the full Qt runtime installed.
        if "libEGL.so.1" in str(exc):
            pytest.skip("Qt GUI smoke test requires the system libEGL.so.1 library.")
        raise

    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    try:
        # The target row stays available while secondary scan settings collapse.
        assert not window.url_input.isHidden()
        window.scan_controls_toggle.setChecked(False)
        assert window.depth_spin.isHidden()
        assert not window.url_input.isHidden()
        window.scan_controls_toggle.setChecked(True)
        assert not window.depth_spin.isHidden()

        # Filters are optional, and can be shown without starting another scan.
        assert window.result_filters_group.isHidden()
        window.filters_toggle.setChecked(True)
        assert not window.result_filters_group.isHidden()
        window.filters_toggle.setChecked(False)
        assert window.result_filters_group.isHidden()

        # Result tabs and table columns can be hidden and restored.
        assert window.tabs.count() > 1
        assert window.tabs.isTabVisible(0)
        window._set_result_panel_visible(0, False)
        assert not window.tabs.isTabVisible(0)
        window._set_result_panel_visible(0, True)
        assert window.tabs.isTabVisible(0)

        table = window.table
        assert not table.isColumnHidden(0)
        window._set_result_column_visible(table, 0, False)
        assert table.isColumnHidden(0)
        window._set_result_column_visible(table, 0, True)
        assert not table.isColumnHidden(0)

        # Focus mode collapses secondary controls, while reset restores defaults.
        window.focus_view_button.setChecked(True)
        assert window.depth_spin.isHidden()
        assert window.result_filters_group.isHidden()
        window._reset_layout()
        assert not window.depth_spin.isHidden()
        assert window.result_filters_group.isHidden()
        assert all(window.tabs.isTabVisible(i) for i in range(window.tabs.count()))
        assert all(not window.table.isColumnHidden(i) for i in range(window.table.columnCount()))
        app.processEvents()
    finally:
        window.close()
        app.processEvents()
