"""Recon Crawler v2 - Desktop Website Crawler for Reconnaissance."""
import sys
from PySide6.QtWidgets import QApplication
from gui.main_window import MainWindow


def _domain_scope_self_test() -> int:
    """Exit nonzero if Public Suffix List data is missing from a source or frozen build."""
    try:
        from recon.domain_scope import registrable_domain

        if registrable_domain("api.example.co.uk") != "example.co.uk":
            return 2
        if registrable_domain("tenant.blogspot.com") != "tenant.blogspot.com":
            return 3
        return 0
    except Exception:
        # Intentionally avoid printing secrets or opening a GUI in the frozen smoke test.
        return 10


def main():
    if "--self-test-domain-scope" in sys.argv:
        return _domain_scope_self_test()

    app = QApplication(sys.argv)
    app.setApplicationName("Recon Crawler")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
