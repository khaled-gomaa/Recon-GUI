"""Main application window."""
import base64
import json
from pathlib import Path
from types import SimpleNamespace

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QGridLayout, QGroupBox, QLineEdit, QSpinBox, QPushButton, QTextEdit,
    QTableWidget, QTableWidgetItem, QTabWidget, QFileDialog, QMessageBox, QCheckBox, QComboBox,
)
from PySide6.QtGui import QColor, QBrush
from PySide6.QtCore import Qt
from gui.status_style import status_colors
from gui.worker import CrawlWorker
from recon.matchers import MatcherFilter
from recon.similarity_detector import SimilarityDetector
from gui.report_export import render_text_report, render_csv_report
from recon.history_store import HistoryStore
from recon.external_tools import available_tools
from gui.tool_worker import ExternalToolWorker


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Recon Crawler v2 - Desktop Website Reconnaissance")
        self.resize(1300, 800)
        self.worker = None
        self.tool_worker = None
        self.recon_report = {}
        self.active_matcher = MatcherFilter()
        self.live_results = []
        self.live_discovery_results = []
        self._build_ui()
        self._refresh_history_for_target()

    def _build_ui(self):
        central = QWidget()
        central.setObjectName("central")
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(18, 16, 18, 14)
        root.setSpacing(12)

        # Header
        header = QFrame()
        header.setObjectName("hero")
        hero_layout = QHBoxLayout(header)
        hero_layout.setContentsMargins(18, 14, 18, 14)
        hero_copy = QVBoxLayout()
        title = QLabel("RECON CRAWLER")
        title.setObjectName("appTitle")
        subtitle = QLabel("Website mapping  •  Hidden routes  •  Content discovery")
        subtitle.setObjectName("appSubtitle")
        hero_copy.addWidget(title)
        hero_copy.addWidget(subtitle)
        hero_layout.addLayout(hero_copy, 1)
        self.status_label = QLabel("READY")
        self.status_label.setObjectName("statusBadge")
        self.status_label.setMinimumWidth(160)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hero_layout.addWidget(self.status_label)
        root.addWidget(header)

        # Target and scan controls
        settings = QGroupBox("Target & scan setup")
        settings.setObjectName("sectionCard")
        grid = QGridLayout(settings)
        grid.setContentsMargins(16, 22, 16, 14)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(10)

        target_label = QLabel("Target URL")
        target_label.setObjectName("fieldLabel")
        self.url_input = QLineEdit("https://example.com")
        self.url_input.setClearButtonEnabled(True)
        self.url_input.setPlaceholderText("https://target-you-are-authorized-to-test.example")
        grid.addWidget(target_label, 0, 0)
        grid.addWidget(self.url_input, 0, 1, 1, 5)

        depth_label = QLabel("Crawl depth")
        depth_label.setObjectName("fieldLabel")
        self.depth_spin = QSpinBox()
        self.depth_spin.setRange(1, 5)
        self.depth_spin.setValue(2)
        self.depth_spin.setToolTip("How many link levels to follow from the starting page.")
        pages_label = QLabel("Max pages")
        pages_label.setObjectName("fieldLabel")
        self.pages_spin = QSpinBox()
        self.pages_spin.setRange(10, 5000)
        self.pages_spin.setValue(200)
        self.pages_spin.setToolTip("Hard cap on pages fetched by the crawl engine.")
        concurrency_label = QLabel("Concurrency")
        concurrency_label.setObjectName("fieldLabel")
        self.conc_spin = QSpinBox()
        self.conc_spin.setRange(1, 20)
        self.conc_spin.setValue(5)
        self.conc_spin.setToolTip("Parallel requests; lower this if the server is sensitive to load.")
        grid.addWidget(depth_label, 1, 0)
        grid.addWidget(self.depth_spin, 1, 1)
        grid.addWidget(pages_label, 1, 2)
        grid.addWidget(self.pages_spin, 1, 3)
        grid.addWidget(concurrency_label, 1, 4)
        grid.addWidget(self.conc_spin, 1, 5)

        wordlist_label = QLabel("Wordlist")
        wordlist_label.setObjectName("fieldLabel")
        self.wordlist_input = QLineEdit()
        self.wordlist_input.setClearButtonEnabled(True)
        self.wordlist_input.setPlaceholderText("Blank uses the bundled common list when Content Discovery is enabled")
        self.wordlist_input.setToolTip("Optional path to a custom newline-delimited wordlist.")
        self.wordlist_input.textChanged.connect(self._wordlist_path_changed)
        browse_btn = QPushButton("Browse…")
        browse_btn.clicked.connect(self._pick_wordlist)
        self.content_discovery_check = QCheckBox("Enable Content Discovery")
        self.content_discovery_check.setChecked(False)
        self.content_discovery_check.setToolTip(
            "Actively check paths from a wordlist. Use only for authorized targets. "
            "HTTP 429 responses trigger a Retry-After cool-down or a safe stop."
        )
        grid.addWidget(wordlist_label, 2, 0)
        grid.addWidget(self.wordlist_input, 2, 1, 1, 3)
        grid.addWidget(browse_btn, 2, 4)
        grid.addWidget(self.content_discovery_check, 2, 5)

        self.start_btn = QPushButton("▶  Start scan")
        self.start_btn.setObjectName("primaryButton")
        self.start_btn.clicked.connect(self._start_crawl)
        self.stop_btn = QPushButton("■  Stop")
        self.stop_btn.setObjectName("dangerButton")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_crawl)
        action_row = QHBoxLayout()
        action_row.addStretch(1)
        action_row.addWidget(self.start_btn)
        action_row.addWidget(self.stop_btn)
        grid.addLayout(action_row, 3, 0, 1, 6)
        root.addWidget(settings)

        # Optional capabilities and session settings; credentials remain in memory only.
        options = QGroupBox("Optional modules & session")
        options.setObjectName("sectionCard")
        options_grid = QGridLayout(options)
        options_grid.setContentsMargins(16, 18, 16, 12)
        options_grid.setHorizontalSpacing(12)
        options_grid.setVerticalSpacing(7)
        self.render_js_check = QCheckBox("Render JavaScript (optional Playwright)")
        self.render_js_check.setToolTip(
            "Renders at most 30 pages; install Playwright and Chromium separately. "
            "Cross-host browser requests are blocked."
        )
        self.passive_check = QCheckBox("Passive sources (crt.sh + Wayback)")
        self.passive_check.setToolTip(
            "Queries public indexes only; discovered hosts are not actively probed."
        )
        options_grid.addWidget(self.render_js_check, 0, 0, 1, 2)
        options_grid.addWidget(self.passive_check, 0, 2, 1, 2)

        token_label = QLabel("Bearer token")
        token_label.setObjectName("fieldLabel")
        self.auth_token_input = QLineEdit()
        self.auth_token_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.auth_token_input.setClearButtonEnabled(True)
        self.auth_token_input.setPlaceholderText("Optional; kept in memory only")
        self.auth_token_input.setToolTip("Sent only in the Authorization header; never written to reports.")
        cookie_label = QLabel("Cookies")
        cookie_label.setObjectName("fieldLabel")
        self.cookie_input = QLineEdit()
        self.cookie_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.cookie_input.setClearButtonEnabled(True)
        self.cookie_input.setPlaceholderText("name=value; other=value")
        self.cookie_input.setToolTip("Optional Cookie header; never written to reports.")
        options_grid.addWidget(token_label, 1, 0)
        options_grid.addWidget(self.auth_token_input, 1, 1)
        options_grid.addWidget(cookie_label, 1, 2)
        options_grid.addWidget(self.cookie_input, 1, 3)

        basic_user_label = QLabel("Basic username")
        basic_user_label.setObjectName("fieldLabel")
        self.basic_user_input = QLineEdit()
        self.basic_user_input.setClearButtonEnabled(True)
        self.basic_user_input.setPlaceholderText("Optional")
        basic_password_label = QLabel("Basic password")
        basic_password_label.setObjectName("fieldLabel")
        self.basic_password_input = QLineEdit()
        self.basic_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.basic_password_input.setClearButtonEnabled(True)
        self.basic_password_input.setPlaceholderText("Optional")
        options_grid.addWidget(basic_user_label, 2, 0)
        options_grid.addWidget(self.basic_user_input, 2, 1)
        options_grid.addWidget(basic_password_label, 2, 2)
        options_grid.addWidget(self.basic_password_input, 2, 3)
        root.addWidget(options)

        # Filters are grouped by intent so Match/Exclude semantics are obvious.
        filters = QGroupBox("Result filters")
        filters.setObjectName("sectionCard")
        filter_outer = QVBoxLayout(filters)
        filter_outer.setContentsMargins(16, 22, 16, 14)
        filter_outer.setSpacing(8)
        filter_header = QHBoxLayout()
        filter_help = QLabel(
            "Keep matching results, or exclude matching results. Values: 200,301  •  "
            "status classes: 2xx,5xx  •  ranges: 1000-2000. Apply locally without rescanning."
        )
        filter_help.setObjectName("mutedText")
        filter_help.setWordWrap(True)
        filter_header.addWidget(filter_help, 1)
        self.apply_filters_btn = QPushButton("Apply filters")
        self.apply_filters_btn.setObjectName("primaryButton")
        self.apply_filters_btn.clicked.connect(self._apply_filters_to_current_results)
        self.clear_filters_btn = QPushButton("Clear")
        self.clear_filters_btn.clicked.connect(self._clear_filters)
        filter_header.addWidget(self.apply_filters_btn)
        filter_header.addWidget(self.clear_filters_btn)
        filter_outer.addLayout(filter_header)

        filter_columns = QHBoxLayout()
        filter_columns.setSpacing(12)

        keep_group = QGroupBox("MATCH  ·  Keep results that match")
        keep_grid = QGridLayout(keep_group)
        keep_grid.setContentsMargins(12, 18, 12, 10)
        keep_grid.setHorizontalSpacing(10)
        keep_grid.setVerticalSpacing(5)
        exclude_group = QGroupBox("FILTER  ·  Exclude results that match")
        exclude_grid = QGridLayout(exclude_group)
        exclude_grid.setContentsMargins(12, 18, 12, 10)
        exclude_grid.setHorizontalSpacing(10)
        exclude_grid.setVerticalSpacing(5)

        self.match_status = QLineEdit()
        self.match_status.setPlaceholderText("200, 2xx")
        self.match_status.setToolTip("Keep response status codes, e.g. 200,301 or 2xx.")
        self.match_words = QLineEdit()
        self.match_words.setPlaceholderText("100-250")
        self.match_words.setToolTip("Keep pages with word counts in these values/ranges.")
        self.match_length = QLineEdit()
        self.match_length.setPlaceholderText("1000-2000")
        self.match_length.setToolTip("Keep response sizes (bytes) in these values/ranges.")
        self.filter_status = QLineEdit()
        self.filter_status.setPlaceholderText("404, 5xx")
        self.filter_status.setToolTip("Remove matching response status codes.")
        self.filter_words = QLineEdit()
        self.filter_words.setPlaceholderText("0-5")
        self.filter_words.setToolTip("Remove responses with word counts in these values/ranges.")
        self.filter_length = QLineEdit()
        self.filter_length.setPlaceholderText("0-500")
        self.filter_length.setToolTip("Remove responses with sizes (bytes) in these values/ranges.")

        keep_fields = (
            ("Status", self.match_status),
            ("Words", self.match_words),
            ("Size (bytes)", self.match_length),
        )
        exclude_fields = (
            ("Status", self.filter_status),
            ("Words", self.filter_words),
            ("Size (bytes)", self.filter_length),
        )
        for column, (label, field) in enumerate(keep_fields):
            caption = QLabel(label)
            caption.setObjectName("fieldLabel")
            keep_grid.addWidget(caption, 0, column)
            keep_grid.addWidget(field, 1, column)
        for column, (label, field) in enumerate(exclude_fields):
            caption = QLabel(label)
            caption.setObjectName("fieldLabel")
            exclude_grid.addWidget(caption, 0, column)
            exclude_grid.addWidget(field, 1, column)

        filter_columns.addWidget(keep_group, 1)
        filter_columns.addWidget(exclude_group, 1)
        filter_outer.addLayout(filter_columns)
        root.addWidget(filters)

        # Main results
        self.tabs = QTabWidget()
        self.tabs.setObjectName("resultsTabs")
        root.addWidget(self.tabs, 1)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setPlaceholderText("Scan progress and rate-limit handling messages appear here.")
        self.tabs.addTab(self.log_view, "Activity")

        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels([
            "URL", "Status", "Redirect chain", "Final URL",
            "Words", "Title", "Content hash", "Favicon",
        ])
        self.table.setColumnWidth(0, 320)
        self.table.setColumnWidth(2, 130)
        self.table.setColumnWidth(3, 220)
        self.tabs.addTab(self.table, "Pages")

        self.discovery_table = QTableWidget(0, 6)
        self.discovery_table.setHorizontalHeaderLabels([
            "URL", "Status", "Size", "Words", "Content type", "Classification",
        ])
        self.discovery_table.setColumnWidth(0, 360)
        self.discovery_table.setColumnWidth(4, 190)
        self.tabs.addTab(self.discovery_table, "Content Discovery")

        self.similarity_view = QTextEdit()
        self.similarity_view.setReadOnly(True)
        self.tabs.addTab(self.similarity_view, "Similar pages")

        self.recon_view = QTextEdit()
        self.recon_view.setReadOnly(True)
        self.tabs.addTab(self.recon_view, "Recon findings")

        self.history_table = QTableWidget(0, 7)
        self.history_table.setHorizontalHeaderLabels([
            "Scan #", "Started", "Status", "Pages", "Added", "Removed", "Changed",
        ])
        self.history_table.setColumnWidth(0, 70)
        self.history_table.setColumnWidth(1, 240)
        self.history_table.setColumnWidth(2, 120)
        self.tabs.addTab(self.history_table, "Scan History")
        self.url_input.editingFinished.connect(self._refresh_history_for_target)

        tool_page = QWidget()
        tool_layout = QVBoxLayout(tool_page)
        tool_controls = QHBoxLayout()
        self.external_tool_combo = QComboBox()
        self.external_tool_combo.addItems(["subfinder", "gau", "nuclei", "ffuf", "nmap"])
        self.check_tools_btn = QPushButton("Check installed tools")
        self.check_tools_btn.clicked.connect(self._check_external_tools)
        self.run_tool_btn = QPushButton("Run selected tool")
        self.run_tool_btn.setObjectName("primaryButton")
        self.run_tool_btn.clicked.connect(self._run_external_tool)
        self.stop_tool_btn = QPushButton("Stop tool")
        self.stop_tool_btn.setObjectName("dangerButton")
        self.stop_tool_btn.setEnabled(False)
        self.stop_tool_btn.clicked.connect(self._stop_external_tool)
        tool_controls.addWidget(QLabel("Tool"))
        tool_controls.addWidget(self.external_tool_combo)
        tool_controls.addWidget(self.check_tools_btn)
        tool_controls.addWidget(self.run_tool_btn)
        tool_controls.addWidget(self.stop_tool_btn)
        tool_layout.addLayout(tool_controls)
        self.external_tool_status = QLabel(
            "Optional CLI integrations. Active tools use conservative request rates; "
            "GUI session cookies/tokens are not passed to CLI tools."
        )
        self.external_tool_status.setWordWrap(True)
        self.external_tool_status.setObjectName("mutedText")
        tool_layout.addWidget(self.external_tool_status)
        self.external_tool_output = QTextEdit()
        self.external_tool_output.setReadOnly(True)
        self.external_tool_output.setPlaceholderText(
            "Installed-tool status and output appear here. Tools run only when explicitly selected."
        )
        tool_layout.addWidget(self.external_tool_output, 1)
        self.tabs.addTab(tool_page, "External Tools")

        for table in (self.table, self.discovery_table, self.history_table):
            self._style_table(table)

        # Export and status footer
        footer = QHBoxLayout()
        export_caption = QLabel("Export report:")
        export_caption.setObjectName("mutedText")
        footer.addWidget(export_caption)
        self.export_txt_btn = QPushButton("Export TXT")
        self.export_txt_btn.setObjectName("secondaryButton")
        self.export_txt_btn.setEnabled(False)
        self.export_txt_btn.clicked.connect(self._export_txt)
        self.export_btn = QPushButton("Export JSON")
        self.export_btn.setObjectName("secondaryButton")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self._export_json)
        self.export_csv_btn = QPushButton("Export CSV")
        self.export_csv_btn.setObjectName("secondaryButton")
        self.export_csv_btn.setEnabled(False)
        self.export_csv_btn.clicked.connect(self._export_csv)
        footer.addWidget(self.export_txt_btn)
        footer.addWidget(self.export_btn)
        footer.addWidget(self.export_csv_btn)
        footer.addStretch(1)
        root.addLayout(footer)

        self.setStyleSheet("""
            QWidget#central {
                background: #f3f6fb;
                color: #1c2940;
                font-family: "Segoe UI", "Inter", sans-serif;
                font-size: 10pt;
            }
            QFrame#hero {
                background: #172b4d;
                border: 1px solid #203b65;
                border-radius: 12px;
            }
            QLabel#appTitle {
                color: #ffffff;
                font-size: 19pt;
                font-weight: 800;
                letter-spacing: 1px;
            }
            QLabel#appSubtitle { color: #c4d2e6; font-size: 9pt; }
            QLabel#statusBadge {
                background: #e0f2e9;
                color: #176448;
                border: 1px solid #b5e4cf;
                border-radius: 8px;
                padding: 7px 12px;
                font-weight: 700;
            }
            QGroupBox#sectionCard {
                background: #ffffff;
                border: 1px solid #dbe3ef;
                border-radius: 10px;
                margin-top: 10px;
                font-weight: 700;
                padding-top: 4px;
            }
            QGroupBox#sectionCard::title {
                subcontrol-origin: margin;
                left: 14px;
                padding: 0 6px;
                color: #203b65;
            }
            QGroupBox {
                border: 1px solid #dbe3ef;
                border-radius: 8px;
                margin-top: 7px;
                font-weight: 600;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 4px;
            }
            QLabel#fieldLabel { color: #42526e; font-weight: 600; }
            QLabel#mutedText { color: #63738b; font-size: 9pt; }
            QLineEdit, QSpinBox, QTextEdit {
                background: #ffffff;
                border: 1px solid #cbd5e1;
                border-radius: 6px;
                padding: 7px 9px;
                selection-background-color: #2563eb;
            }
            QLineEdit:focus, QSpinBox:focus, QTextEdit:focus {
                border: 1px solid #3b82f6;
            }
            QPushButton {
                background: #ffffff;
                color: #24364f;
                border: 1px solid #cbd5e1;
                border-radius: 7px;
                padding: 8px 13px;
                font-weight: 600;
            }
            QPushButton:hover { background: #edf4ff; border-color: #93b4e8; }
            QPushButton:disabled { color: #9aa7b8; background: #edf0f5; }
            QPushButton#primaryButton {
                background: #2563eb; color: #ffffff; border: 1px solid #1d4ed8;
            }
            QPushButton#primaryButton:hover { background: #1d4ed8; }
            QPushButton#dangerButton {
                background: #fff1f2; color: #be123c; border: 1px solid #fecdd3;
            }
            QPushButton#dangerButton:hover { background: #ffe4e6; }
            QPushButton#secondaryButton {
                background: #ffffff; color: #1d4ed8; border: 1px solid #bfdbfe;
            }
            QTabWidget::pane {
                background: #ffffff;
                border: 1px solid #dbe3ef;
                border-radius: 8px;
                top: -1px;
            }
            QTabBar::tab {
                background: #e8edf5;
                color: #53647e;
                padding: 10px 16px;
                margin-right: 3px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                font-weight: 600;
            }
            QTabBar::tab:selected { background: #ffffff; color: #1d4ed8; }
            QTableWidget {
                background: #ffffff;
                alternate-background-color: #f7f9fc;
                gridline-color: #e7edf5;
                border: none;
                selection-background-color: #dbeafe;
                selection-color: #172b4d;
            }
            QHeaderView::section {
                background: #edf2f8;
                color: #344863;
                padding: 8px;
                border: none;
                border-bottom: 1px solid #d7e0ec;
                font-weight: 700;
            }
            QCheckBox { color: #344863; font-weight: 600; spacing: 6px; }
        """)

    def _check_external_tools(self):
        tools = available_tools()
        lines = ["Optional command-line integrations:"]
        for name, path in tools.items():
            lines.append(f"{name}: {path if path else 'not installed / not on PATH'}")
        self.external_tool_output.setPlainText("\n".join(lines))
        missing = sum(1 for path in tools.values() if not path)
        self.external_tool_status.setText(
            f"{len(tools) - missing}/{len(tools)} tools available. "
            "Install missing tools separately and ensure they are on PATH."
        )

    def _run_external_tool(self):
        if self.tool_worker and self.tool_worker.isRunning():
            QMessageBox.information(self, "Tool already running", "Stop the current external tool first.")
            return
        tool = self.external_tool_combo.currentText()
        target = self.url_input.text().strip()
        from urllib.parse import urlparse
        parsed = urlparse(target)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            QMessageBox.warning(self, "Invalid target", "Enter a valid HTTP(S) target URL first.")
            return
        wordlist_path = None
        if tool == "ffuf":
            selected = self.wordlist_input.text().strip()
            wordlist_path = selected or str(self._bundled_wordlist_path())
            if not Path(wordlist_path).is_file():
                QMessageBox.warning(self, "Wordlist not found", f"Cannot find: {wordlist_path}")
                return
        if tool in {"nuclei", "ffuf", "nmap"}:
            answer = QMessageBox.question(
                self, "Confirm authorization",
                f"{tool} sends active requests to {target}. External tools do not share the crawler 429 retry manager. Continue only if this target is "
                "within your explicit authorization. Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.external_tool_output.clear()
        self.external_tool_status.setText(f"Running {tool} with a 5-minute timeout...")
        self.run_tool_btn.setEnabled(False)
        self.stop_tool_btn.setEnabled(True)
        self.tool_worker = ExternalToolWorker(tool, target, wordlist_path)
        self.tool_worker.completed.connect(self._on_external_tool_finished)
        self.tool_worker.error.connect(self._on_external_tool_error)
        self.tool_worker.start()

    def _stop_external_tool(self):
        if self.tool_worker and self.tool_worker.isRunning():
            self.tool_worker.stop()
            self.external_tool_status.setText("Stop requested; terminating tool process.")
            self.stop_tool_btn.setEnabled(False)

    def _on_external_tool_finished(self, result: dict):
        self.external_tool_output.setPlainText("\n".join(result.get("output", [])))
        tool = result.get("tool", "tool")
        code = result.get("return_code", "?")
        status = "stopped" if result.get("stopped") else "timed out" if result.get("timed_out") else f"exit code {code}"
        self.external_tool_status.setText(f"{tool} finished: {status}.")
        self.run_tool_btn.setEnabled(True)
        self.stop_tool_btn.setEnabled(False)

    def _on_external_tool_error(self, message: str):
        self.external_tool_output.setPlainText(message)
        self.external_tool_status.setText("External tool failed.")
        self.run_tool_btn.setEnabled(True)
        self.stop_tool_btn.setEnabled(False)

    def _refresh_history_for_target(self):
        """Refresh persistent history for the current URL without starting a network scan."""
        if not hasattr(self, "history_table"):
            return
        target = self.url_input.text().strip()
        if not target:
            self.history_table.setRowCount(0)
            return
        try:
            self._populate_history(HistoryStore().recent_scans(target))
        except (ValueError, OSError) as exc:
            self.history_table.setRowCount(0)
        except Exception as exc:
            self.history_table.setRowCount(0)
            if hasattr(self, "log_view"):
                self.log_view.append(f"[History] Unable to read local history: {type(exc).__name__}: {exc}")

    def _populate_history(self, scans):
        self.history_table.setRowCount(0)
        for scan in scans or []:
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            values = (
                scan.get("scan_id", ""), scan.get("started_at", scan.get("completed_at", "")),
                scan.get("status", ""), scan.get("page_count", 0),
                scan.get("added_count", 0), scan.get("removed_count", 0),
                scan.get("changed_count", 0),
            )
            for column, value in enumerate(values):
                self.history_table.setItem(row, column, QTableWidgetItem(str(value)))

    @staticmethod
    def _style_table(table: QTableWidget):
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setWordWrap(False)
        table.verticalHeader().setVisible(False)
        table.setShowGrid(False)
        table.setSortingEnabled(False)
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setMinimumSectionSize(75)

    def _pick_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Wordlist", "", "Text Files (*.txt);;All Files (*)"
        )
        if path:
            self.wordlist_input.setText(path)
            self.content_discovery_check.setChecked(True)

    def _wordlist_path_changed(self, value: str):
        # Pasting or typing a list path opts into active content discovery.
        if value.strip() and not self.content_discovery_check.isChecked():
            self.content_discovery_check.setChecked(True)

    @staticmethod
    def _bundled_wordlist_path() -> Path:
        return Path(__file__).resolve().parent.parent / "wordlists" / "common.txt"

    def _build_matcher(self) -> MatcherFilter:
        return MatcherFilter(
            match_status=self.match_status.text().strip(),
            match_length=self.match_length.text().strip(),
            match_words=self.match_words.text().strip(),
            filter_status=self.filter_status.text().strip(),
            filter_length=self.filter_length.text().strip(),
            filter_words=self.filter_words.text().strip(),
        )

    def _clear_filters(self):
        for field in (
            self.match_status, self.match_words, self.match_length,
            self.filter_status, self.filter_words, self.filter_length,
        ):
            field.clear()
        self._apply_filters_to_current_results()

    def _start_crawl(self):
        url = self.url_input.text().strip()
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            QMessageBox.warning(self, "Invalid URL", "Enter a full http:// or https:// URL.")
            return

        try:
            matcher = self._build_matcher()
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid filter", str(exc))
            return

        wordlist_path = None
        if self.content_discovery_check.isChecked():
            selected_path = self.wordlist_input.text().strip()
            wordlist_path = Path(selected_path) if selected_path else self._bundled_wordlist_path()
            if not wordlist_path.is_file():
                QMessageBox.warning(
                    self, "Wordlist not found",
                    f"Cannot find content-discovery wordlist:\n{wordlist_path}",
                )
                return
            wordlist_path = str(wordlist_path)

        auth_token = self.auth_token_input.text().strip()
        cookie_header = self.cookie_input.text().strip()
        basic_user = self.basic_user_input.text()
        basic_password = self.basic_password_input.text()
        if bool(basic_user) != bool(basic_password):
            QMessageBox.warning(self, "Incomplete Basic Auth", "Enter both the Basic username and password.")
            return
        if auth_token and basic_user:
            QMessageBox.warning(self, "Conflicting authentication", "Use either a Bearer token or Basic Auth, not both.")
            return
        request_headers = {}
        if auth_token:
            request_headers["Authorization"] = (
                auth_token if auth_token.lower().startswith("bearer ") else "Bearer " + auth_token
            )
        elif basic_user:
            encoded = base64.b64encode(f"{basic_user}:{basic_password}".encode("utf-8")).decode("ascii")
            request_headers["Authorization"] = "Basic " + encoded
        if cookie_header:
            request_headers["Cookie"] = cookie_header

        self.active_matcher = matcher
        self.live_results = []
        self.live_discovery_results = []
        self.log_view.clear()
        self.table.setRowCount(0)
        self.discovery_table.setRowCount(0)
        self.recon_view.clear()
        self.similarity_view.clear()
        self.recon_report = {}
        self.export_btn.setEnabled(False)
        self.export_txt_btn.setEnabled(False)
        self.export_csv_btn.setEnabled(False)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Crawling...")

        self.worker = CrawlWorker(
            url=url,
            max_depth=self.depth_spin.value(),
            max_pages=self.pages_spin.value(),
            concurrency=self.conc_spin.value(),
            wordlist_path=wordlist_path,
            matcher=matcher,
            render_javascript=self.render_js_check.isChecked(),
            passive_discovery=self.passive_check.isChecked(),
            request_headers=request_headers,
        )
        self.worker.log_message.connect(self._append_log)
        self.worker.page_crawled.connect(self._on_page_crawled)
        self.worker.discovery_result.connect(self._on_discovery_result)
        self.worker.finished.connect(self._on_finished)
        self.worker.error.connect(self._on_error)
        self.worker.start()

    def _stop_crawl(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self._append_log("[Stop requested — allowing in-flight requests to finish]")
            self.stop_btn.setEnabled(False)

    def _append_log(self, msg: str):
        self.log_view.append(msg)

    def _on_page_crawled(self, result):
        # Keep every result so the user can change filters without repeating the scan.
        self.live_results.append(result)
        if not self.active_matcher.matches(result):
            return
        self._append_page_row(
            result.url, result.status, result.redirect_chain, result.final_url,
            result.word_count, result.title, result.content_hash, "--",
        )

    def _append_page_row(
        self, url, status, redirect_chain, final_url,
        word_count, title, content_hash, favicon_hash="--",
    ):
        row = self.table.rowCount()
        self.table.insertRow(row)
        if redirect_chain:
            chain = " -> ".join(str(item["status"]) for item in redirect_chain)
            chain += f" -> {status}"
        else:
            chain = "--"
        visible_final_url = final_url if final_url != url else "--"
        values = (url, str(status), chain, visible_final_url, str(word_count),
                  title, content_hash, favicon_hash or "--")
        for column, value in enumerate(values):
            self.table.setItem(row, column, QTableWidgetItem(value))
        self._color_row(self.table, row, status)

    def _rebuild_table_from_filtered(self, filtered, favicon_hash):
        self.table.setRowCount(0)
        for result in filtered:
            self._append_page_row(
                result["url"], result["status"], result["redirect_chain"],
                result["final_url"], result["word_count"], result["title"],
                result["content_hash"], favicon_hash or "--",
            )

    @staticmethod
    def _color_row(table: QTableWidget, row: int, status: int):
        foreground, background = status_colors(status)
        for column in range(table.columnCount()):
            item = table.item(row, column)
            if item is not None:
                item.setForeground(QBrush(QColor(foreground)))
                item.setBackground(QBrush(QColor(background)))

    def _on_discovery_result(self, result: dict):
        self.live_discovery_results.append(result)
        self._append_content_discovery_row(result)

    def _append_content_discovery_row(self, result: dict):
        proxy = SimpleNamespace(
            status=result.get("status", 0),
            content_length=result.get("size", 0),
            word_count=result.get("word_count", 0),
        )
        if not self.active_matcher.matches(proxy):
            return

        row = self.discovery_table.rowCount()
        self.discovery_table.insertRow(row)
        if result.get("baseline_match"):
            classification = "Likely wildcard response"
        elif result.get("potential_hit"):
            classification = "Potential hit"
        else:
            classification = "Response (not considered a hit)"

        values = (
            result.get("url", ""),
            str(result.get("status", "")),
            str(result.get("size", "")),
            str(result.get("word_count", "")),
            result.get("content_type", ""),
            classification,
        )
        for column, value in enumerate(values):
            self.discovery_table.setItem(row, column, QTableWidgetItem(value))
        self._color_row(self.discovery_table, row, result.get("status", 0))

    def _rebuild_content_discovery_table(self, results):
        self.discovery_table.setRowCount(0)
        for result in results:
            self._append_content_discovery_row(result)

    @staticmethod
    def _page_filter_proxy(page: dict):
        return SimpleNamespace(
            url=page.get("url", ""),
            status=page.get("status", 0),
            content_length=page.get("content_length", 0),
            word_count=page.get("word_count", 0),
            content_hash=page.get("content_hash", ""),
            text_hash=page.get("text_hash", ""),
            title=page.get("title", ""),
            final_url=page.get("final_url", ""),
            redirect_chain=page.get("redirect_chain", []),
        )

    def _refresh_report_filters(self):
        pages = self.recon_report.get("pages", [])
        filtered = [
            page for page in pages
            if self.active_matcher.matches(self._page_filter_proxy(page))
        ]
        self.recon_report["filtered_pages"] = filtered
        self.recon_report["matcher_description"] = self.active_matcher.describe()
        self.recon_report["matcher_applied"] = not self.active_matcher.is_empty()
        filtered_proxies = [self._page_filter_proxy(page) for page in filtered]
        self.recon_report["similarity"] = SimilarityDetector().analyze(filtered_proxies)

    def _apply_filters_to_current_results(self):
        try:
            self.active_matcher = self._build_matcher()
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid filter", str(exc))
            return

        if self.recon_report.get("pages") is not None and "pages" in self.recon_report:
            # Filtering is local: no network requests or repeat scan are needed.
            self._on_finished(self.recon_report)
        else:
            self.table.setRowCount(0)
            for result in self.live_results:
                if self.active_matcher.matches(result):
                    self._append_page_row(
                        result.url, result.status, result.redirect_chain,
                        result.final_url, result.word_count, result.title,
                        result.content_hash, "--",
                    )
            self._rebuild_content_discovery_table(self.live_discovery_results)
            self.status_label.setText("FILTERS APPLIED")
            self._append_log(f"[Filters] Applied locally: {self.active_matcher.describe()}")

    def _on_finished(self, report: dict):
        self.recon_report = report
        self._refresh_report_filters()
        favicon = report.get("favicon_hash", "")
        filtered = report.get("filtered_pages", [])
        self._rebuild_table_from_filtered(filtered, favicon)
        self._rebuild_content_discovery_table(report.get("wordlist_results", []))
        self._render_recon(report)
        self._render_similarity(report.get("similarity", {}))
        self.export_btn.setEnabled(True)
        self.export_txt_btn.setEnabled(True)
        self.export_csv_btn.setEnabled(True)
        self._populate_history(report.get("recent_scans", []))
        self._reset_buttons()

        sim = report.get("similarity", {})
        kept = len(filtered)
        total = len(report.get("pages", []))
        matcher_note = ""
        if report.get("matcher_applied"):
            matcher_note = f" | matched {kept}/{total}"
        path_results = report.get("wordlist_results", [])
        path_hits = report.get("wordlist_hits", [])
        discovery_note = (
            f" | content discovery {len(path_results)} responses/{len(path_hits)} potential hits"
            if path_results or self.content_discovery_check.isChecked() else ""
        )
        crawler_limited = report.get("crawler_rate_limited_stop", False)
        discovery_limited = report.get("wordlist_rate_limited_stop", False)
        if report.get("stopped_by_user"):
            self.status_label.setText(f"STOPPED  ·  {total} pages")
        elif crawler_limited or discovery_limited:
            self.status_label.setText("PARTIAL  ·  RATE LIMITED")
        else:
            self.status_label.setText(f"COMPLETE  ·  {total} pages")

        summary = (
            f"[Summary] {total} pages crawled; {kept} match current filters; "
            f"{len(path_results)} content-discovery responses; {len(path_hits)} potential hits; "
            f"{len(sim.get('exact_duplicates', []))} duplicate groups; "
            f"{len(sim.get('soft_404_candidates', []))} soft-404 candidates."
        )
        self._append_log(summary)
        if crawler_limited or discovery_limited:
            self._append_log(
                "[429] Scanning stopped or partially resumed to respect the target's "
                "rate limit. No rate-limit bypass was attempted."
            )

    def _on_error(self, msg: str):
        self._append_log(f"[FATAL] {msg}")
        self._reset_buttons()
        self.status_label.setText("SCAN ERROR")

    def _reset_buttons(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _render_recon(self, report: dict):
        lines = []
        lines.append("=== FAVICON HASH ===")
        lines.append(f"  {report.get('favicon_hash', '') or '(not found)'}\n")

        lines.append("=== MATCHERS APPLIED ===")
        lines.append(f"  {report.get('matcher_description', '')}\n")

        for section in ("emails", "subdomains", "endpoints",
                        "discovered_routes", "js_files", "source_maps"):
            lines.append(f"=== {section.upper().replace('_', ' ')} ===")
            for item in report.get(section, []):
                lines.append(f"  - {item}")
            lines.append("")

        lines.append("=== WORDLIST HITS ===")
        for hit in report.get("wordlist_hits", []):
            lines.append(f"  [{hit['status']}] {hit['url']} -- {hit['size']} bytes")
        lines.append("")

        lines.append("=== SECURITY HEADERS ===")
        for audit in report.get("header_audits", []):
            lines.append(f"  URL: {audit['url']}")
            lines.append(f"    Present: {list(audit['present'].keys()) or 'None'}")
            lines.append(f"    Missing: {audit['missing'] or 'None'}")

        lines.append("=== HTML FORMS (NO SUBMISSION PERFORMED) ===")
        for form in report.get("forms", []):
            csrf_note = "CSRF-like field present" if form.get("csrf_field_present") else "No obvious CSRF field"
            lines.append(
                f"  [{form.get('method', 'GET')}] {form.get('action', '')} "
                f"(fields={form.get('field_count', 0)}, {csrf_note})"
            )
            for field in form.get("fields", []):
                lines.append(
                    f"    - {field.get('name', '')}: {field.get('type', '')}"
                    + (" [required]" if field.get("required") else "")
                )
        lines.append("")
        lines.append("=== JSON-LD / STRUCTURED DATA ===")
        for item in report.get("json_ld", []):
            lines.append(f"  - {item.get('type', '(unknown type)')} | {item.get('name', '')} | {item.get('page', '')}")
        lines.append("")
        lines.append("=== SENSITIVE-DATA CANDIDATES (VALUES REDACTED) ===")
        for item in report.get("sensitive_findings", []):
            lines.append(
                f"  [{item.get('severity', 'medium')}] {item.get('type', '')} "
                f"on {item.get('page', '')} ({item.get('source', '')}) — [REDACTED]"
            )
        lines.append("")
        for section in ("passive_subdomains", "historical_urls"):
            lines.append(f"=== {section.upper().replace('_', ' ')} ===")
            for value in report.get(section, []):
                lines.append(f"  - {value}")
            lines.append("")
        lines.append("=== PASSIVE SOURCE NOTES ===")
        for item in report.get("passive_sources", []):
            lines.append(f"  - {item.get('name')}: {item.get('status')} ({item.get('count', 0)} items)")
        for item in report.get("passive_errors", []):
            lines.append(f"  - Warning: {item}")
        lines.append("")
        diff = report.get("history_diff", {})
        lines.append("=== SCAN HISTORY COMPARISON ===")
        lines.append(f"  Current scan: {report.get('scan_id', '(not saved)')}")
        lines.append(f"  Previous scan: {diff.get('previous_scan_id', '(first scan)')}")
        lines.append(
            f"  Added: {diff.get('added_count', 0)} | Removed: {diff.get('removed_count', 0)} "
            f"| Changed: {diff.get('changed_count', 0)}"
        )
        for key, label in (("added_urls", "NEW"), ("removed_urls", "REMOVED"), ("changed_urls", "CHANGED")):
            for url in diff.get(key, []):
                lines.append(f"  [{label}] {url}")
        if report.get("history_error"):
            lines.append(f"  History warning: {report['history_error']}")
        lines.append("")
        lines.append("=== CONFIGURATION ===")
        lines.append(f"  JavaScript rendering enabled: {report.get('rendering_enabled', False)}")
        lines.append(f"  Rendered pages: {report.get('rendered_pages', 0)}")
        lines.append(f"  robots.txt: {report.get('robots_url', '(not read)')}")
        lines.append(f"  Crawl-delay: {report.get('crawl_delay_seconds', 0)} seconds")
        lines.append(f"  Authentication configured: {report.get('auth_configured', False)}")
        lines.append(f"  Authentication fields: {', '.join(report.get('auth_types', [])) or '(none)'}")

        self.recon_view.setPlainText("\n".join(lines))

    def _render_similarity(self, sim: dict):
        lines = []
        lines.append("=== EXACT DUPLICATES ===")
        for g in sim.get("exact_duplicates", []):
            lines.append(f"  hash {g['hash']} ({len(g['urls'])} pages):")
            for u in g["urls"]:
                lines.append(f"    {u}")

        lines.append("\n=== SOFT-404 CANDIDATES ===")
        for g in sim.get("soft_404_candidates", []):
            tag = "IDENTICAL" if g["identical_content"] else "similar"
            lines.append(f"  [{tag}] ~{g['word_count_bucket']}w x {g['count']} pages")
            for p in g["pages"]:
                lines.append(f"    [{p['word_count']}w] {p['url']} - {p['title'][:40]}")

        lines.append("\n=== PATH VARIANTS ===")
        for g in sim.get("same_path_variants", []):
            tag = "SAME" if g["identical_content"] else "varies"
            lines.append(
                f"  [{tag}] {g['path_pattern']} x{g['count']} "
                f"words {g['word_count_range']}"
            )
            for p in g["pages"]:
                lines.append(f"    [{p['status']}/{p['word_count']}w] {p['url']}")

        lines.append("\n=== REDIRECT DUPLICATES ===")
        for g in sim.get("redirect_duplicates", []):
            lines.append(f"  final: {g['final_url']}")
            for s in g["sources"]:
                lines.append(f"    <- {s}")

        self.similarity_view.setPlainText("\n".join(lines))

    def _export_txt(self):
        if not self.recon_report:
            QMessageBox.information(self, "No report", "Run a scan before exporting a report.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Recon TXT", "recon_report.txt", "Text Files (*.txt);;All Files (*)"
        )
        if not path:
            return
        try:
            text_report = render_text_report(self.recon_report)
            with open(path, "w", encoding="utf-8", newline="\n") as report_file:
                report_file.write(text_report)
            self.status_label.setText("TXT EXPORTED")
            self._append_log(f"[Export] Text report saved: {path}")
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", f"Could not write TXT report:\n{exc}")

    def _export_csv(self):
        if not self.recon_report:
            QMessageBox.information(self, "No report", "Run a scan before exporting a report.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Recon CSV", "recon_report.csv", "CSV (*.csv);;All Files (*)"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as report_file:
                report_file.write(render_csv_report(self.recon_report))
            self.status_label.setText("CSV EXPORTED")
            self._append_log(f"[Export] CSV report saved: {path}")
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", f"Could not write CSV report:\n{exc}")

    def _export_json(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Recon JSON", "recon_report.json", "JSON (*.json)"
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.recon_report, f, indent=2, ensure_ascii=False)
            self.status_label.setText("JSON EXPORTED")
            self._append_log(f"[Export] JSON report saved: {path}")
