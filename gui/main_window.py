"""Main application window."""
import base64
import json
from pathlib import Path
from types import SimpleNamespace

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QGridLayout, QGroupBox, QLineEdit, QSpinBox, QPushButton, QTextEdit,
    QTableWidget, QTableWidgetItem, QTabWidget, QFileDialog, QMessageBox, QCheckBox, QComboBox, QToolButton, QHeaderView,
)
from PySide6.QtGui import QColor, QBrush
from PySide6.QtCore import Qt, QTimer
from gui.status_style import status_colors
from gui.worker import CrawlWorker
from recon.matchers import MatcherFilter
from recon.similarity_detector import SimilarityDetector
from gui.report_export import render_text_report, render_csv_report
from recon.history_store import HistoryStore
from recon.external_tools import available_tools
from gui.tool_worker import ExternalToolWorker
from gui.scope_worker import ScopeVerifyWorker
from recon.scope_verifier import normalize_in_scope_hosts


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Recon Crawler v2 - Desktop Website Reconnaissance")
        self.resize(1400, 900)
        self.setMinimumSize(1050, 700)
        self.worker = None
        self.tool_worker = None
        self.scope_worker = None
        self.scope_verification_by_host = {}
        self.recon_report = {}
        self.active_matcher = MatcherFilter()
        self.live_results = []
        self.live_discovery_results = []
        self._pending_page_results = []
        self._pending_discovery_results = []
        self._build_ui()
        self._result_batch_timer = QTimer(self)
        self._result_batch_timer.setInterval(100)
        self._result_batch_timer.timeout.connect(self._flush_pending_rows)
        self._refresh_history_for_target()

    def _build_ui(self):
        central = QWidget()
        central.setObjectName("central")
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(10, 8, 10, 8)
        root.setSpacing(5)

        # Header
        header = QFrame()
        header.setObjectName("hero")
        hero_layout = QHBoxLayout(header)
        hero_layout.setContentsMargins(14, 7, 14, 7)
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
        self.status_label.setMinimumWidth(126)
        self.status_label.setMaximumHeight(36)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hero_layout.addWidget(self.status_label)
        header.setMaximumHeight(78)
        root.addWidget(header)

        # Compact scan bar: keep the target and primary controls visible.
        settings = QGroupBox("Scan setup")
        settings.setObjectName("sectionCard")
        grid = QGridLayout(settings)
        grid.setContentsMargins(12, 18, 12, 8)
        grid.setHorizontalSpacing(9)
        grid.setVerticalSpacing(5)

        target_label = QLabel("Target")
        target_label.setObjectName("fieldLabel")
        self.url_input = QLineEdit("https://example.com")
        self.url_input.setClearButtonEnabled(True)
        self.url_input.setPlaceholderText("https://target-you-are-authorized-to-test.example")
        self.url_input.setMinimumHeight(30)
        self.url_input.setMaximumHeight(34)
        grid.addWidget(target_label, 0, 0)
        grid.addWidget(self.url_input, 0, 1, 1, 5)

        self.start_btn = QPushButton("▶ Start")
        self.start_btn.setObjectName("primaryButton")
        self.start_btn.setMinimumHeight(31)
        self.start_btn.clicked.connect(self._start_crawl)
        self.stop_btn = QPushButton("■ Stop")
        self.stop_btn.setObjectName("dangerButton")
        self.stop_btn.setMinimumHeight(31)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_crawl)
        grid.addWidget(self.start_btn, 0, 6)
        grid.addWidget(self.stop_btn, 0, 7)

        depth_label = QLabel("Depth")
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
        concurrency_label = QLabel("Parallel")
        concurrency_label.setObjectName("fieldLabel")
        self.conc_spin = QSpinBox()
        self.conc_spin.setRange(1, 20)
        self.conc_spin.setValue(5)
        self.conc_spin.setToolTip("Lower this if the server is sensitive to load.")
        for widget in (self.depth_spin, self.pages_spin, self.conc_spin):
            widget.setMinimumHeight(29)
            widget.setMaximumHeight(33)
        grid.addWidget(depth_label, 1, 0)
        grid.addWidget(self.depth_spin, 1, 1)
        grid.addWidget(pages_label, 1, 2)
        grid.addWidget(self.pages_spin, 1, 3)
        grid.addWidget(concurrency_label, 1, 4)
        grid.addWidget(self.conc_spin, 1, 5)

        self.content_discovery_check = QCheckBox("Content Discovery")
        self.content_discovery_check.setChecked(False)
        self.content_discovery_check.setToolTip(
            "Checks wordlist paths on authorized targets. HTTP 429 invokes a compliant pause or safe stop."
        )
        grid.addWidget(self.content_discovery_check, 1, 6, 1, 2)

        wordlist_label = QLabel("Wordlist")
        wordlist_label.setObjectName("fieldLabel")
        self.wordlist_input = QLineEdit()
        self.wordlist_input.setClearButtonEnabled(True)
        self.wordlist_input.setPlaceholderText("Optional .txt path; blank uses the bundled list when Content Discovery is enabled")
        self.wordlist_input.setToolTip("Optional path to a custom newline-delimited wordlist.")
        self.wordlist_input.textChanged.connect(self._wordlist_path_changed)
        self.wordlist_input.setMinimumHeight(29)
        self.wordlist_input.setMaximumHeight(33)
        browse_btn = QPushButton("Browse…")
        browse_btn.setMinimumHeight(29)
        browse_btn.setMaximumHeight(33)
        browse_btn.clicked.connect(self._pick_wordlist)
        grid.addWidget(wordlist_label, 2, 0)
        grid.addWidget(self.wordlist_input, 2, 1, 1, 6)
        grid.addWidget(browse_btn, 2, 7)

        extensions_label = QLabel("Extensions")
        extensions_label.setObjectName("fieldLabel")
        self.extensions_input = QLineEdit()
        self.extensions_input.setClearButtonEnabled(True)
        self.extensions_input.setPlaceholderText(
            "Blank = built-in list; otherwise comma-separated, e.g. .php,.json,.bak,.old"
        )
        self.extensions_input.setToolTip(
            "Content Discovery adds the exact path plus each extension here. "
            "No fixed 500-word truncation is applied; very large lists may take a long time."
        )
        self.extensions_input.setMinimumHeight(29)
        self.extensions_input.setMaximumHeight(33)
        grid.addWidget(extensions_label, 3, 0)
        grid.addWidget(self.extensions_input, 3, 1, 1, 7)

        word_cap_label = QLabel("Word cap (0 = all)")
        word_cap_label.setObjectName("fieldLabel")
        self.word_cap_spin = QSpinBox()
        self.word_cap_spin.setRange(0, 10000000)
        self.word_cap_spin.setValue(0)
        self.word_cap_spin.setToolTip(
            "0 processes every valid wordlist entry. A positive cap is explicit and makes coverage partial if more entries remain."
        )
        candidate_cap_label = QLabel("Path cap (0 = all)")
        candidate_cap_label.setObjectName("fieldLabel")
        self.candidate_cap_spin = QSpinBox()
        self.candidate_cap_spin.setRange(0, 10000000)
        self.candidate_cap_spin.setValue(0)
        self.candidate_cap_spin.setToolTip(
            "0 checks every unique path generated by the wordlist and extension list. Large lists can take substantial time."
        )
        for widget in (self.word_cap_spin, self.candidate_cap_spin):
            widget.setMinimumHeight(29)
            widget.setMaximumHeight(33)
        grid.addWidget(word_cap_label, 4, 0)
        grid.addWidget(self.word_cap_spin, 4, 1)
        grid.addWidget(candidate_cap_label, 4, 2)
        grid.addWidget(self.candidate_cap_spin, 4, 3)
        cap_hint = QLabel("Unlimited by default; HTTP 429 still pauses/stops safely.")
        cap_hint.setObjectName("mutedText")
        grid.addWidget(cap_hint, 4, 4, 1, 4)

        for column, stretch in ((1, 2), (3, 1), (5, 1), (6, 1), (7, 0)):
            grid.setColumnStretch(column, stretch)
        root.addWidget(settings)

        # Keep advanced modules hidden until requested so results remain the main workspace.
        self.advanced_toggle = QToolButton()
        self.advanced_toggle.setObjectName("advancedToggle")
        self.advanced_toggle.setText("Advanced options & session  ▸")
        self.advanced_toggle.setCheckable(True)
        self.advanced_toggle.setChecked(False)
        self.advanced_toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        self.advanced_toggle.toggled.connect(self._set_advanced_visible)
        root.addWidget(self.advanced_toggle, 0, Qt.AlignmentFlag.AlignLeft)

        options = QGroupBox("Optional modules & session")
        options.setObjectName("sectionCard")
        self.advanced_options_group = options
        options_grid = QGridLayout(options)
        options_grid.setContentsMargins(12, 16, 12, 8)
        options_grid.setHorizontalSpacing(9)
        options_grid.setVerticalSpacing(5)
        self.render_js_check = QCheckBox("Render JavaScript (Playwright)")
        self.render_js_check.setToolTip(
            "Renders crawled HTML pages up to the configured Max pages limit (max 5000). Install Playwright and Chromium separately; cross-origin requests are blocked."
        )
        self.passive_check = QCheckBox("Passive sources (crt.sh + Wayback)")
        self.passive_check.setToolTip("Queries public indexes only; discovered hosts are not actively probed.")
        options_grid.addWidget(self.render_js_check, 0, 0, 1, 2)
        options_grid.addWidget(self.passive_check, 0, 2, 1, 2)
        self.subfinder_check = QCheckBox("Subfinder (passive)")
        self.subfinder_check.setChecked(True)
        self.subfinder_check.setToolTip(
            "Run Subfinder only if installed. It queries passive sources and does not crawl discovered hosts."
        )
        options_grid.addWidget(self.subfinder_check, 0, 4, 1, 2)

        self.manual_browser_check = QCheckBox("Manual browser session + request capture")
        self.manual_browser_check.setChecked(False)
        self.manual_browser_check.setToolTip(
            "Optional headed Chromium session before crawling. Log in and browse manually; "
            "same-host request methods, URL parameter names, responses, and cookie metadata are captured. "
            "Cookie/token values are not added to reports."
        )
        options_grid.addWidget(self.manual_browser_check, 3, 0, 1, 3)
        self.crawl_historical_check = QCheckBox("Crawl same-host historical URLs")
        self.crawl_historical_check.setToolTip(
            "Active requests to up to 50 historical URLs from public indexes. "
            "Off by default; normal host scope, page limits, and rate limits still apply."
        )
        self.crawl_historical_check.setEnabled(False)
        self.passive_check.toggled.connect(self.crawl_historical_check.setEnabled)
        options_grid.addWidget(self.crawl_historical_check, 3, 3, 1, 3)
        capture_duration_label = QLabel("Manual capture window")
        capture_duration_label.setObjectName("fieldLabel")
        self.manual_browser_duration_spin = QSpinBox()
        self.manual_browser_duration_spin.setRange(30, 600)
        self.manual_browser_duration_spin.setValue(180)
        self.manual_browser_duration_spin.setSuffix(" seconds")
        self.manual_browser_duration_spin.setToolTip(
            "How long the visible browser stays open for manual login and navigation (30–600 seconds)."
        )
        self.manual_browser_duration_spin.setMinimumHeight(29)
        self.manual_browser_duration_spin.setMaximumHeight(33)
        options_grid.addWidget(capture_duration_label, 4, 0)
        options_grid.addWidget(self.manual_browser_duration_spin, 4, 1, 1, 2)

        token_label = QLabel("Bearer token")
        token_label.setObjectName("fieldLabel")
        self.auth_token_input = QLineEdit()
        self.auth_token_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.auth_token_input.setClearButtonEnabled(True)
        self.auth_token_input.setPlaceholderText("Optional; memory only")
        self.auth_token_input.setToolTip("Sent only in the Authorization header; never written to reports.")
        cookie_label = QLabel("Cookies")
        cookie_label.setObjectName("fieldLabel")
        self.cookie_input = QLineEdit()
        self.cookie_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.cookie_input.setClearButtonEnabled(True)
        self.cookie_input.setPlaceholderText("name=value; other=value")
        self.cookie_input.setToolTip("Optional Cookie header; never written to reports.")
        basic_user_label = QLabel("Basic user")
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
        for widget in (
            self.auth_token_input, self.cookie_input, self.basic_user_input,
            self.basic_password_input,
        ):
            widget.setMinimumHeight(29)
            widget.setMaximumHeight(33)
        options_grid.addWidget(token_label, 1, 0)
        options_grid.addWidget(self.auth_token_input, 1, 1)
        options_grid.addWidget(cookie_label, 1, 2)
        options_grid.addWidget(self.cookie_input, 1, 3)
        options_grid.addWidget(basic_user_label, 2, 0)
        options_grid.addWidget(self.basic_user_input, 2, 1)
        options_grid.addWidget(basic_password_label, 2, 2)
        options_grid.addWidget(self.basic_password_input, 2, 3)
        options.setVisible(False)
        root.addWidget(options)

        # Compact filter bar: two rows of matching/exclusion fields instead of nested cards.
        filters = QGroupBox("Result filters")
        filters.setObjectName("sectionCard")
        filter_outer = QVBoxLayout(filters)
        filter_outer.setContentsMargins(10, 16, 10, 8)
        filter_outer.setSpacing(4)
        filter_header = QHBoxLayout()
        filter_help = QLabel("Keep / exclude values, status classes (2xx) and numeric ranges. Filters apply locally.")
        filter_help.setObjectName("mutedText")
        filter_header.addWidget(filter_help, 1)
        self.apply_filters_btn = QPushButton("Apply")
        self.apply_filters_btn.setObjectName("primaryButton")
        self.apply_filters_btn.setMinimumHeight(29)
        self.apply_filters_btn.setMaximumHeight(32)
        self.apply_filters_btn.clicked.connect(self._apply_filters_to_current_results)
        self.clear_filters_btn = QPushButton("Clear")
        self.clear_filters_btn.setMinimumHeight(29)
        self.clear_filters_btn.setMaximumHeight(32)
        self.clear_filters_btn.clicked.connect(self._clear_filters)
        filter_header.addWidget(self.apply_filters_btn)
        filter_header.addWidget(self.clear_filters_btn)
        filter_outer.addLayout(filter_header)

        filter_grid = QGridLayout()
        filter_grid.setContentsMargins(0, 0, 0, 0)
        filter_grid.setHorizontalSpacing(8)
        filter_grid.setVerticalSpacing(4)
        keep_label = QLabel("KEEP")
        keep_label.setObjectName("fieldLabel")
        exclude_label = QLabel("EXCLUDE")
        exclude_label.setObjectName("fieldLabel")
        self.match_status = QLineEdit()
        self.match_status.setPlaceholderText("Status: 200, 2xx")
        self.match_status.setToolTip("Keep response status codes, e.g. 200,301 or 2xx.")
        self.match_words = QLineEdit()
        self.match_words.setPlaceholderText("Words: 100-250")
        self.match_words.setToolTip("Keep pages with word counts in these values/ranges.")
        self.match_length = QLineEdit()
        self.match_length.setPlaceholderText("Size: 1000-2000")
        self.match_length.setToolTip("Keep response sizes (bytes) in these values/ranges.")
        self.filter_status = QLineEdit()
        self.filter_status.setPlaceholderText("Status: 404, 5xx")
        self.filter_status.setToolTip("Exclude matching response status codes.")
        self.filter_words = QLineEdit()
        self.filter_words.setPlaceholderText("Words: 0-5")
        self.filter_words.setToolTip("Exclude responses with word counts in these values/ranges.")
        self.filter_length = QLineEdit()
        self.filter_length.setPlaceholderText("Size: 0-500")
        self.filter_length.setToolTip("Exclude responses with sizes (bytes) in these values/ranges.")
        for widget in (
            self.match_status, self.match_words, self.match_length,
            self.filter_status, self.filter_words, self.filter_length,
        ):
            widget.setMinimumHeight(29)
            widget.setMaximumHeight(33)
        filter_grid.addWidget(keep_label, 0, 0)
        filter_grid.addWidget(self.match_status, 0, 1)
        filter_grid.addWidget(self.match_words, 0, 2)
        filter_grid.addWidget(self.match_length, 0, 3)
        filter_grid.addWidget(exclude_label, 1, 0)
        filter_grid.addWidget(self.filter_status, 1, 1)
        filter_grid.addWidget(self.filter_words, 1, 2)
        filter_grid.addWidget(self.filter_length, 1, 3)
        filter_grid.setColumnMinimumWidth(0, 58)
        for column in (1, 2, 3):
            filter_grid.setColumnStretch(column, 1)
        filter_outer.addLayout(filter_grid)
        root.addWidget(filters)

        # A single search field filters visible rows across the result tables.
        search_row = QHBoxLayout()
        search_label = QLabel("Search results")
        search_label.setObjectName("fieldLabel")
        self.results_search = QLineEdit()
        self.results_search.setClearButtonEnabled(True)
        self.results_search.setPlaceholderText("Search URL, endpoint, parameter, status, finding…")
        self.results_search.setMinimumHeight(29)
        self.results_search.setMaximumHeight(33)
        self.results_search.textChanged.connect(self._filter_result_tables)
        search_row.addWidget(search_label)
        search_row.addWidget(self.results_search, 1)
        root.addLayout(search_row)

        # Main results
        self.tabs = QTabWidget()
        self.tabs.setObjectName("resultsTabs")
        self.tabs.setDocumentMode(True)
        self.tabs.setMinimumHeight(260)
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
        self.table.setColumnWidth(1, 74)
        self.table.setColumnWidth(2, 130)
        self.table.setColumnWidth(4, 70)
        self.table.setColumnWidth(6, 125)
        self.table.setColumnWidth(7, 110)
        page_header = self.table.horizontalHeader()
        page_header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        page_header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        page_header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        page_header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.tabs.addTab(self.table, "Pages")

        self.endpoint_table = QTableWidget(0, 6)
        self.endpoint_table.setHorizontalHeaderLabels([
            "Endpoint", "Methods", "Sources", "Parameters", "Pages", "Locations",
        ])
        self.endpoint_table.setColumnWidth(1, 90)
        self.endpoint_table.setColumnWidth(2, 180)
        self.endpoint_table.setColumnWidth(3, 100)
        self.endpoint_table.setColumnWidth(4, 80)
        self.endpoint_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.endpoint_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.tabs.addTab(self.endpoint_table, "Endpoints")

        self.parameter_table = QTableWidget(0, 6)
        self.parameter_table.setHorizontalHeaderLabels([
            "Parameter", "Classification", "Sources", "Occurrences", "Methods", "Pages",
        ])
        self.parameter_table.setColumnWidth(0, 150)
        self.parameter_table.setColumnWidth(1, 130)
        self.parameter_table.setColumnWidth(3, 95)
        self.parameter_table.setColumnWidth(4, 90)
        self.parameter_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.parameter_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.tabs.addTab(self.parameter_table, "Parameters")

        self.findings_table = QTableWidget(0, 6)
        self.findings_table.setHorizontalHeaderLabels([
            "Severity", "Category", "Finding", "Confidence", "Evidence", "Recommendation",
        ])
        self.findings_table.setColumnWidth(0, 85)
        self.findings_table.setColumnWidth(1, 130)
        self.findings_table.setColumnWidth(2, 260)
        self.findings_table.setColumnWidth(3, 100)
        self.findings_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.findings_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.tabs.addTab(self.findings_table, "Findings")

        self.discovery_table = QTableWidget(0, 6)
        self.discovery_table.setHorizontalHeaderLabels([
            "URL", "Status", "Size", "Words", "Content type", "Classification",
        ])
        self.discovery_table.setColumnWidth(1, 74)
        self.discovery_table.setColumnWidth(2, 80)
        self.discovery_table.setColumnWidth(3, 70)
        self.discovery_table.setColumnWidth(5, 150)
        discovery_header = self.discovery_table.horizontalHeader()
        discovery_header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        discovery_header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.tabs.addTab(self.discovery_table, "Content Discovery")

        self.network_table = QTableWidget(0, 8)
        self.network_table.setHorizontalHeaderLabels([
            "Endpoint", "Method", "Status", "Resource type", "Query names",
            "Body names", "Source", "Initiating page",
        ])
        self.network_table.setColumnWidth(1, 82)
        self.network_table.setColumnWidth(2, 72)
        self.network_table.setColumnWidth(3, 105)
        self.network_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.network_table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
        self.tabs.addTab(self.network_table, "Network Requests")

        self.cookie_table = QTableWidget(0, 6)
        self.cookie_table.setHorizontalHeaderLabels([
            "Page / URL", "Cookie name", "Domain", "Path", "Attributes", "Source",
        ])
        self.cookie_table.setColumnWidth(1, 150)
        self.cookie_table.setColumnWidth(2, 140)
        self.cookie_table.setColumnWidth(3, 100)
        self.cookie_table.setColumnWidth(4, 180)
        self.cookie_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tabs.addTab(self.cookie_table, "Cookie Map")

        # Passive discoveries are inert until the operator selects and verifies them.
        scope_page = QWidget()
        self.subdomain_page = scope_page
        scope_layout = QVBoxLayout(scope_page)
        scope_layout.setContentsMargins(8, 8, 8, 8)
        scope_help = QLabel(
            "Subdomains are discovery candidates, not automatic crawl targets. Select only hosts "
            "covered by your authorization, then run DNS + one unauthenticated HTTP HEAD check. "
            "Redirects are not followed and session cookies/tokens are not sent. Select one host "
            "and use it as the next scan target when ready."
        )
        scope_help.setWordWrap(True)
        scope_help.setObjectName("mutedText")
        scope_layout.addWidget(scope_help)
        scope_actions = QHBoxLayout()
        self.verify_subdomains_btn = QPushButton("Verify selected (DNS + HTTP HEAD)")
        self.verify_subdomains_btn.setObjectName("primaryButton")
        self.verify_subdomains_btn.setEnabled(False)
        self.verify_subdomains_btn.clicked.connect(self._verify_selected_subdomains)
        self.use_subdomain_btn = QPushButton("Use selected host as target")
        self.use_subdomain_btn.setObjectName("secondaryButton")
        self.use_subdomain_btn.setEnabled(False)
        self.use_subdomain_btn.clicked.connect(self._use_selected_subdomain)
        scope_actions.addWidget(self.verify_subdomains_btn)
        scope_actions.addWidget(self.use_subdomain_btn)
        scope_actions.addStretch(1)
        scope_layout.addLayout(scope_actions)
        self.subdomain_table = QTableWidget(0, 7)
        self.subdomain_table.setHorizontalHeaderLabels([
            "Select", "Hostname", "Discovery source", "DNS", "Resolved IPs", "HTTP HEAD", "Probed URL",
        ])
        self.subdomain_table.setColumnWidth(0, 58)
        self.subdomain_table.setColumnWidth(2, 155)
        self.subdomain_table.setColumnWidth(3, 105)
        self.subdomain_table.setColumnWidth(4, 220)
        self.subdomain_table.setColumnWidth(5, 130)
        self.subdomain_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.subdomain_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.tabs.addTab(scope_page, "Subdomains")
        scope_layout.addWidget(self.subdomain_table, 1)

        self.similarity_view = QTextEdit()
        self.similarity_view.setReadOnly(True)
        self.tabs.addTab(self.similarity_view, "Similar pages")

        self.recon_view = QTextEdit()
        self.recon_view.setReadOnly(True)
        self.tabs.addTab(self.recon_view, "Recon summary")

        self.history_table = QTableWidget(0, 10)
        self.history_table.setHorizontalHeaderLabels([
            "Scan #", "Started", "Status", "Pages", "New URLs", "Removed",
            "Changed", "New endpoints", "New parameters", "New findings",
        ])
        self.history_table.setColumnWidth(0, 70)
        self.history_table.setColumnWidth(1, 180)
        self.history_table.setColumnWidth(2, 105)
        self.history_table.horizontalHeader().setSectionResizeMode(9, QHeaderView.ResizeMode.Stretch)
        self.tabs.addTab(self.history_table, "Scan History")
        self.url_input.editingFinished.connect(self._refresh_history_for_target)

        tool_page = QWidget()
        tool_layout = QVBoxLayout(tool_page)
        tool_controls = QHBoxLayout()
        self.external_tool_combo = QComboBox()
        self.external_tool_combo.addItems(["gau", "nuclei", "ffuf"])
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

        for table in (
            self.table, self.endpoint_table, self.parameter_table, self.findings_table,
            self.discovery_table, self.network_table, self.cookie_table,
            self.subdomain_table, self.history_table,
        ):
            self._style_table(table)
            table.horizontalHeader().sortIndicatorChanged.connect(
                lambda _column, _order: self._filter_result_tables(self.results_search.text())
            )

        # Export and status footer
        footer = QHBoxLayout()
        self.import_har_btn = QPushButton("Import HAR / Burp")
        self.import_har_btn.setObjectName("secondaryButton")
        self.import_har_btn.setToolTip(
            "Import a browser or Burp-exported HAR file. Only same-host request metadata is merged; "
            "query/body/cookie values are not retained."
        )
        self.import_har_btn.clicked.connect(self._import_har_file)
        footer.addWidget(self.import_har_btn)
        footer.addSpacing(12)
        footer.addWidget(QLabel("Export report:"))
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
                border-radius: 10px;
            }
            QLabel#appTitle {
                color: #ffffff;
                font-size: 15pt;
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
                border-radius: 8px;
                margin-top: 7px;
                font-weight: 700;
                padding-top: 2px;
            }
            QGroupBox#sectionCard::title {
                subcontrol-origin: margin;
                left: 14px;
                padding: 0 6px;
                color: #203b65;
            }
            QGroupBox {
                border: 1px solid #dbe3ef;
                border-radius: 7px;
                margin-top: 6px;
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
                border-radius: 5px;
                selection-background-color: #2563eb;
            }
            QLineEdit, QSpinBox {
                padding: 2px 7px;
                min-height: 25px;
            }
            QTextEdit {
                padding: 5px;
            }
            QLineEdit:focus, QSpinBox:focus, QTextEdit:focus {
                border: 1px solid #3b82f6;
            }
            QPushButton {
                background: #ffffff;
                color: #24364f;
                border: 1px solid #cbd5e1;
                border-radius: 7px;
                padding: 4px 10px;
                min-height: 25px;
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
                padding: 6px 12px;
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
                padding: 4px 6px;
                border: none;
                border-bottom: 1px solid #d7e0ec;
                font-weight: 700;
            }
            QCheckBox { color: #344863; font-weight: 600; spacing: 5px; }
            QToolButton#advancedToggle {
                color: #1d4ed8;
                font-weight: 600;
                padding: 2px 5px;
                border: none;
                background: transparent;
            }
            QToolButton#advancedToggle:hover { color: #1e40af; }
        """)

    def _result_tables(self):
        return [
            getattr(self, name, None) for name in (
                "table", "endpoint_table", "parameter_table", "findings_table",
                "discovery_table", "network_table", "cookie_table", "subdomain_table", "history_table",
            )
        ]

    def _set_result_table_sorting(self, enabled: bool):
        for table in (item for item in self._result_tables() if item is not None):
            table.setSortingEnabled(enabled)

    def _filter_result_tables(self, query: str):
        """Filter visible rows across data tables without triggering another scan."""
        needle = (query or "").strip().casefold()
        for table in (item for item in self._result_tables() if item is not None):
            for row in range(table.rowCount()):
                self._filter_table_row(table, row, needle)

    @staticmethod
    def _filter_table_row(table: QTableWidget, row: int, needle: str):
        if not needle:
            table.setRowHidden(row, False)
            return
        values = []
        for column in range(table.columnCount()):
            item = table.item(row, column)
            if item is not None:
                values.append(item.text())
        table.setRowHidden(row, needle not in " ".join(values).casefold())

    def _populate_endpoint_parameter_findings(self, report: dict):
        """Populate structured result tables from the unified scan report."""
        self.endpoint_table.setRowCount(0)
        for record in report.get("endpoint_inventory", []) or []:
            values = (
                record.get("endpoint", ""),
                ", ".join(record.get("methods", []) or []),
                ", ".join(record.get("sources", []) or []),
                ", ".join(record.get("parameters", []) or []),
                record.get("location_count", 0),
                " | ".join(record.get("locations", []) or []),
            )
            row = self.endpoint_table.rowCount()
            self.endpoint_table.insertRow(row)
            for column, value in enumerate(values):
                self.endpoint_table.setItem(row, column, QTableWidgetItem(str(value)))
            self._filter_table_row(self.endpoint_table, row, self.results_search.text().strip().casefold())

        self.parameter_table.setRowCount(0)
        for record in report.get("parameters", []) or []:
            values = (
                record.get("name", ""),
                record.get("classification", ""),
                ", ".join(record.get("sources", []) or []),
                record.get("occurrences", 0),
                ", ".join(record.get("methods", []) or []),
                " | ".join(record.get("locations", []) or []),
            )
            row = self.parameter_table.rowCount()
            self.parameter_table.insertRow(row)
            for column, value in enumerate(values):
                self.parameter_table.setItem(row, column, QTableWidgetItem(str(value)))
            self._filter_table_row(self.parameter_table, row, self.results_search.text().strip().casefold())

        self.findings_table.setRowCount(0)
        severity_colors = {
            "critical": ("#7f1d1d", "#fee2e2"),
            "high": ("#991b1b", "#fee2e2"),
            "medium": ("#92400e", "#fef3c7"),
            "low": ("#1e40af", "#dbeafe"),
            "info": ("#334155", "#f1f5f9"),
        }
        for finding in report.get("related_findings", []) or []:
            evidence = " | ".join(str(item) for item in finding.get("evidence", []) or [])
            values = (
                finding.get("severity", "info"), finding.get("category", ""),
                finding.get("title", ""), finding.get("confidence", ""),
                evidence, finding.get("recommendation", ""),
            )
            row = self.findings_table.rowCount()
            self.findings_table.insertRow(row)
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                self.findings_table.setItem(row, column, item)
                foreground, background = severity_colors.get(
                    str(finding.get("severity", "info")).lower(), severity_colors["info"]
                )
                if column == 0:
                    item.setForeground(QBrush(QColor(foreground)))
                    item.setBackground(QBrush(QColor(background)))
            self._filter_table_row(self.findings_table, row, self.results_search.text().strip().casefold())

    def _checked_subdomain_hosts(self):
        hosts = []
        for row in range(self.subdomain_table.rowCount()):
            checkbox = self.subdomain_table.item(row, 0)
            hostname = self.subdomain_table.item(row, 1)
            if checkbox and hostname and checkbox.checkState() == Qt.CheckState.Checked:
                hosts.append(hostname.text().strip())
        return list(dict.fromkeys(host for host in hosts if host))

    def _populate_subdomain_table(self, report: dict):
        """List discovered hosts with source labels, but never activate them automatically."""
        self.subdomain_table.setRowCount(0)
        self.scope_verification_by_host = {}
        sources_by_host = {}
        for host in report.get("passive_subdomains", []) or []:
            sources_by_host.setdefault(str(host).lower().rstrip("."), set()).add("Passive indexes")
        for host in report.get("subfinder_subdomains", []) or []:
            sources_by_host.setdefault(str(host).lower().rstrip("."), set()).add("Subfinder")
        for host in report.get("subdomains", []) or []:
            sources_by_host.setdefault(str(host).lower().rstrip("."), set()).add("Crawled content")
        for hostname, sources in sorted(sources_by_host.items()):
            if not hostname or any(char.isspace() for char in hostname):
                continue
            row = self.subdomain_table.rowCount()
            self.subdomain_table.insertRow(row)
            check_item = QTableWidgetItem()
            check_item.setFlags(
                Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsUserCheckable
            )
            check_item.setCheckState(Qt.CheckState.Unchecked)
            self.subdomain_table.setItem(row, 0, check_item)
            values = (hostname, ", ".join(sorted(sources)), "Not checked", "--", "Not checked", "--")
            for offset, value in enumerate(values, start=1):
                self.subdomain_table.setItem(row, offset, QTableWidgetItem(str(value)))
            self._filter_table_row(self.subdomain_table, row, self.results_search.text().strip().casefold())
        count = self.subdomain_table.rowCount()
        self.verify_subdomains_btn.setEnabled(count > 0)
        self.use_subdomain_btn.setEnabled(count > 0)
        self.tabs.setTabText(self.tabs.indexOf(self.subdomain_page), f"Subdomains ({count})")

    def _verify_selected_subdomains(self):
        if self.scope_worker and self.scope_worker.isRunning():
            QMessageBox.information(self, "Verification running", "Wait for the current verification to finish.")
            return
        selected = self._checked_subdomain_hosts()
        if not selected:
            QMessageBox.information(self, "Select hosts", "Check one or more hosts in the Subdomains table first.")
            return
        target = str(self.recon_report.get("target") or self.url_input.text()).strip()
        try:
            eligible = normalize_in_scope_hosts(target, selected)
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid target", str(exc))
            return
        eligible_set = set(eligible)
        for hostname in selected:
            if hostname not in eligible_set:
                row = self._subdomain_row_for_host(hostname)
                if row >= 0:
                    self.subdomain_table.item(row, 3).setText("Not tested")
                    self.subdomain_table.item(row, 5).setText("Not eligible for subdomain probe")
        if not eligible:
            QMessageBox.warning(
                self, "No eligible hosts",
                "No selected host is an eligible subdomain of the inferred root. The apex/root host and hosts outside that root are not probed by this action.",
            )
            return
        self.verify_subdomains_btn.setEnabled(False)
        self.status_label.setText("VERIFYING SCOPE...")
        self.scope_worker = ScopeVerifyWorker(target, eligible)
        self.scope_worker.log_message.connect(self._append_log)
        self.scope_worker.completed.connect(self._on_scope_verification_complete)
        self.scope_worker.failed.connect(self._on_scope_verification_error)
        self.scope_worker.start()

    def _subdomain_row_for_host(self, hostname: str) -> int:
        for row in range(self.subdomain_table.rowCount()):
            item = self.subdomain_table.item(row, 1)
            if item and item.text().casefold() == str(hostname).casefold():
                return row
        return -1

    def _on_scope_verification_complete(self, result: dict):
        # Preserve this operator-initiated verification in the current exportable report.
        self.recon_report["subdomain_verification"] = result
        for record in result.get("results", []) or []:
            hostname = record.get("host", "")
            row = self._subdomain_row_for_host(hostname)
            self.scope_verification_by_host[hostname] = record
            if row < 0:
                continue
            self.subdomain_table.item(row, 3).setText(
                "Resolved" if record.get("dns_status") == "resolved" else record.get("dns_status", "unknown")
            )
            self.subdomain_table.item(row, 4).setText(", ".join(record.get("ip_addresses", []) or []) or "--")
            status = record.get("http_status")
            if status is None:
                http_text = record.get("http_result", "not checked")
            else:
                http_text = f"{status} ({record.get('http_result', 'responded')})"
            self.subdomain_table.item(row, 5).setText(http_text)
            self.subdomain_table.item(row, 6).setText(record.get("http_url", "") or "--")
            if record.get("error"):
                self.subdomain_table.item(row, 5).setToolTip("Connection detail: " + record["error"])
        note = (
            f"Scope verification finished: {result.get('verified_count', 0)} host(s) checked; "
            f"{result.get('skipped_count', 0)} skipped."
        )
        if result.get("truncated"):
            note += " The verification cap was reached; selected hosts not listed in results remain unchecked."
        self._append_log("[Scope] " + note)
        self.status_label.setText("READY")
        self.verify_subdomains_btn.setEnabled(self.subdomain_table.rowCount() > 0)
        self._filter_result_tables(self.results_search.text())

    def _on_scope_verification_error(self, message: str):
        self._append_log("[Scope] Verification failed: " + message)
        self.status_label.setText("READY")
        self.verify_subdomains_btn.setEnabled(self.subdomain_table.rowCount() > 0)
        QMessageBox.warning(self, "Verification failed", message)

    def _use_selected_subdomain(self):
        selected = self._checked_subdomain_hosts()
        if len(selected) != 1:
            QMessageBox.information(
                self, "Select one host",
                "Check exactly one hostname to make it the next scan target. No request is sent by this action.",
            )
            return
        hostname = selected[0]
        verification = self.scope_verification_by_host.get(hostname, {})
        probed_url = str(verification.get("http_url") or "")
        scheme = "http" if probed_url.startswith("http://") else "https"
        self.url_input.setText(f"{scheme}://{hostname}/")
        self.url_input.setFocus()
        self._append_log(
            f"[Scope] Target set to {hostname}. Start a new scan only if that host is in your authorized scope."
        )
        self._refresh_history_for_target()

    def _populate_network_cookie_tables(self, report: dict):
        """Show safe request metadata and cookie names/attributes; never expose values."""
        self.network_table.setRowCount(0)
        for record in report.get("network_observations", []) or []:
            values = (
                record.get("url", ""),
                record.get("method", ""),
                "--" if record.get("status") is None else record.get("status"),
                record.get("resource_type", ""),
                ", ".join(record.get("query_parameters", []) or []),
                ", ".join(record.get("body_parameters", []) or []),
                record.get("source", ""),
                record.get("page", ""),
            )
            row = self.network_table.rowCount()
            self.network_table.insertRow(row)
            for column, value in enumerate(values):
                self.network_table.setItem(row, column, QTableWidgetItem(str(value)))
            self._filter_table_row(self.network_table, row, self.results_search.text().strip().casefold())

        self.cookie_table.setRowCount(0)
        for record in report.get("cookie_map", []) or []:
            attrs = []
            if record.get("secure"):
                attrs.append("Secure")
            if record.get("httponly"):
                attrs.append("HttpOnly")
            if record.get("samesite"):
                attrs.append("SameSite=" + str(record.get("samesite")))
            values = (
                record.get("url", ""),
                record.get("name", ""),
                record.get("domain", ""),
                record.get("path", ""),
                ", ".join(attrs),
                record.get("source", ""),
            )
            row = self.cookie_table.rowCount()
            self.cookie_table.insertRow(row)
            for column, value in enumerate(values):
                self.cookie_table.setItem(row, column, QTableWidgetItem(str(value)))
            self._filter_table_row(self.cookie_table, row, self.results_search.text().strip().casefold())

    def _set_advanced_visible(self, visible: bool):
        """Show optional renderer/passive/auth fields only when explicitly requested."""
        self.advanced_options_group.setVisible(visible)
        self.advanced_toggle.setText(
            "Advanced options & session  ▾" if visible
            else "Advanced options & session  ▸"
        )

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
        if tool in {"nuclei", "ffuf"}:
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
                scan.get("changed_count", 0), scan.get("added_endpoint_count", 0),
                scan.get("added_parameter_count", 0), scan.get("added_finding_count", 0),
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
        table.setMinimumHeight(220)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(26)
        table.setShowGrid(False)
        table.setSortingEnabled(False)
        table.horizontalHeader().setStretchLastSection(False)
        table.horizontalHeader().setMinimumHeight(29)
        table.horizontalHeader().setMinimumSectionSize(72)
        table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

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
        self._set_result_table_sorting(False)
        self.live_results = []
        self.live_discovery_results = []
        self._pending_page_results.clear()
        self._pending_discovery_results.clear()
        self._result_batch_timer.stop()
        self.log_view.clear()
        self.table.setRowCount(0)
        self.endpoint_table.setRowCount(0)
        self.parameter_table.setRowCount(0)
        self.findings_table.setRowCount(0)
        self.discovery_table.setRowCount(0)
        if hasattr(self, "network_table"):
            self.network_table.setRowCount(0)
            self.cookie_table.setRowCount(0)
        self.results_search.clear()
        self.recon_view.clear()
        self.similarity_view.clear()
        self.recon_report = {}
        self.tabs.setTabText(self.tabs.indexOf(self.table), "Pages")
        self.tabs.setTabText(self.tabs.indexOf(self.endpoint_table), "Endpoints")
        self.tabs.setTabText(self.tabs.indexOf(self.parameter_table), "Parameters")
        self.tabs.setTabText(self.tabs.indexOf(self.findings_table), "Findings")
        self.tabs.setTabText(self.tabs.indexOf(self.discovery_table), "Content Discovery")
        self.tabs.setCurrentWidget(self.log_view)
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
            crawl_historical_urls=self.crawl_historical_check.isChecked(),
            wordlist_extensions=(
                [""] + [item.strip() for item in self.extensions_input.text().split(",") if item.strip()]
                if self.extensions_input.text().strip() else None
            ),
            use_subfinder=self.subfinder_check.isChecked(),
            manual_browser_session=self.manual_browser_check.isChecked(),
            manual_browser_duration=self.manual_browser_duration_spin.value(),
            wordlist_max_words=self.word_cap_spin.value(),
            wordlist_max_candidates=self.candidate_cap_spin.value(),
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
        # Queue UI work so a fast crawl cannot stall on thousands of individual row insertions.
        self.live_results.append(result)
        self._pending_page_results.append(result)
        if not self._result_batch_timer.isActive():
            self._result_batch_timer.start()

    def _flush_pending_rows(self):
        """Render a bounded batch of pending results while keeping painting responsive."""
        page_batch = self._pending_page_results[:120]
        discovery_batch = self._pending_discovery_results[:120]
        del self._pending_page_results[:len(page_batch)]
        del self._pending_discovery_results[:len(discovery_batch)]
        if not self._pending_page_results and not self._pending_discovery_results:
            self._result_batch_timer.stop()
        for table in (self.table, self.discovery_table):
            table.setUpdatesEnabled(False)
        try:
            for result in page_batch:
                if self.active_matcher.matches(result):
                    self._append_page_row(
                        result.url, result.status, result.redirect_chain, result.final_url,
                        result.word_count, result.title, result.content_hash, "--",
                    )
            for result in discovery_batch:
                self._append_content_discovery_row(result)
        finally:
            for table in (self.table, self.discovery_table):
                table.setUpdatesEnabled(True)

    def _clear_pending_result_batches(self):
        self._result_batch_timer.stop()
        self._pending_page_results.clear()
        self._pending_discovery_results.clear()

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
        self._filter_table_row(self.table, row, self.results_search.text().strip().casefold())

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
        self._pending_discovery_results.append(result)
        if not self._result_batch_timer.isActive():
            self._result_batch_timer.start()

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
        self._filter_table_row(
            self.discovery_table, row, self.results_search.text().strip().casefold()
        )

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
            self._clear_pending_result_batches()
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
        self._clear_pending_result_batches()
        self._set_result_table_sorting(False)
        self.recon_report = report
        self._refresh_report_filters()
        favicon = report.get("favicon_hash", "")
        filtered = report.get("filtered_pages", [])
        self._rebuild_table_from_filtered(filtered, favicon)
        self._rebuild_content_discovery_table(report.get("wordlist_results", []))
        self._populate_endpoint_parameter_findings(report)
        self._populate_network_cookie_tables(report)
        self._populate_subdomain_table(report)
        self._render_recon(report)
        self._render_similarity(report.get("similarity", {}))
        self.export_btn.setEnabled(True)
        self.export_txt_btn.setEnabled(True)
        self.export_csv_btn.setEnabled(True)
        self._populate_history(report.get("recent_scans", []))
        self.tabs.setTabText(self.tabs.indexOf(self.table), f"Pages ({len(filtered)})")
        self.tabs.setTabText(
            self.tabs.indexOf(self.endpoint_table),
            f"Endpoints ({len(report.get('endpoint_inventory', []))})",
        )
        self.tabs.setTabText(
            self.tabs.indexOf(self.network_table),
            f"Network Requests ({len(report.get('network_observations', []))})",
        )
        self.tabs.setTabText(
            self.tabs.indexOf(self.cookie_table),
            f"Cookie Map ({len(report.get('cookie_map', []))})",
        )
        self.tabs.setTabText(
            self.tabs.indexOf(self.subdomain_table.parentWidget()),
            f"Subdomains ({self.subdomain_table.rowCount()})",
        )
        self.tabs.setTabText(
            self.tabs.indexOf(self.parameter_table),
            f"Parameters ({len(report.get('parameters', []))})",
        )
        self.tabs.setTabText(
            self.tabs.indexOf(self.findings_table),
            f"Findings ({len(report.get('related_findings', []))})",
        )
        self.tabs.setTabText(
            self.tabs.indexOf(self.discovery_table),
            f"Content Discovery ({len(report.get('wordlist_results', []))})",
        )
        self._set_result_table_sorting(True)
        self._filter_result_tables(self.results_search.text())
        self.tabs.setCurrentWidget(self.table)
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
        page_limited = report.get("page_limit_reached", False)
        depth_limited = report.get("depth_limit_reached", False)
        wordlist_limited = report.get("wordlist_candidate_limit_reached", False)
        content_limited = report.get("content_limit_reached", False)
        if report.get("stopped_by_user"):
            self.status_label.setText(f"STOPPED  ·  {total} pages")
        elif crawler_limited or discovery_limited:
            self.status_label.setText("PARTIAL  ·  RATE LIMITED")
        elif page_limited or depth_limited or wordlist_limited or content_limited:
            reasons = []
            if page_limited:
                reasons.append("PAGE")
            if depth_limited:
                reasons.append("DEPTH")
            if wordlist_limited:
                reasons.append("WORDLIST")
            if content_limited:
                reasons.append("CONTENT")
            self.status_label.setText("PARTIAL  ·  " + "/".join(reasons) + " LIMIT")
        else:
            self.status_label.setText(f"COMPLETE  ·  {total} pages")

        coverage_summary = report.get("coverage_summary", {}) or {}
        content_cap_note = (
            f" | truncated body/asset records: {len(report.get('body_truncated_pages', []))} page bodies, "
            f"{len(report.get('truncated_js_files', []))} JS files, "
            f"{len(report.get('truncated_wordlist_urls', []))} wordlist responses"
            if content_limited else ""
        )
        summary = (
            f"[Summary] {total} pages crawled; {kept} match current filters; "
            f"{len(path_results)} content-discovery responses; {len(path_hits)} potential hits; "
            f"{len(report.get('endpoint_inventory', []))} endpoints; "
            f"{len(report.get('parameters', []))} parameter names; "
            f"{len(report.get('network_observations', []))} runtime network requests; "
            f"{len(report.get('cookie_map', []))} cookie metadata records; "
            f"{report.get('wordlist_words_loaded', 0)} wordlist words / "
            f"{report.get('wordlist_candidates', 0)} candidates; "
            f"{len(report.get('related_findings', []))} review findings; "
            f"{len(sim.get('exact_duplicates', []))} duplicate groups; "
            f"{len(sim.get('soft_404_candidates', []))} soft-404 candidates."
            f"{content_cap_note}"
        )
        self._append_log(summary)
        if page_limited:
            self._append_log("[LIMIT] Page limit was reached; undiscovered same-host links remain in the queue/frontier.")
        if depth_limited:
            self._append_log("[LIMIT] Depth limit was reached while additional same-host links remained unvisited.")
        if crawler_limited or discovery_limited:
            self._append_log(
                "[429] Scanning stopped or partially resumed to respect the target's "
                "rate limit. No rate-limit bypass was attempted."
            )

    def _on_error(self, msg: str):
        self._flush_pending_rows()
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
        lines.append("=== COVERAGE / INCOMPLETE CONTENT ===")
        coverage = report.get("coverage_summary", {}) or {}
        if coverage:
            lines.append(
                f"  Pages fetched: {coverage.get('pages_crawled', 0)} / configured cap {coverage.get('page_cap', 0)}; "
                f"maximum depth: {coverage.get('max_depth', 0)}"
            )
            lines.append(
                f"  JavaScript files: {coverage.get('javascript_files_attempted', 0)} attempted / "
                f"{coverage.get('javascript_files_discovered', 0)} discovered; "
                f"{coverage.get('javascript_files_truncated', 0)} truncated"
            )
            lines.append(
                f"  Wordlist words: {coverage.get('wordlist_words_loaded', 0)} / cap "
                f"{coverage.get('wordlist_max_words', 0) or 'unlimited'}; "
                f"word cap reached: {coverage.get('wordlist_word_limit_reached', False)}"
            )
            lines.append(
                f"  Generated paths: {coverage.get('wordlist_candidates', 0)} / cap "
                f"{coverage.get('wordlist_max_candidates', 0) or 'unlimited'}; "
                f"path cap reached: {coverage.get('wordlist_path_limit_reached', False)}"
            )
            lines.append(
                f"  Truncated response bodies: {coverage.get('response_bodies_truncated', 0)}; "
                f"content limit reached: {coverage.get('content_limit_reached', False)}"
            )
        for note in report.get("content_limit_notes", []) or []:
            lines.append(f"  WARNING: {note}")
        lines.append("")
        lines.append("=== CONFIGURATION ===")
        lines.append(f"  JavaScript rendering enabled: {report.get('rendering_enabled', False)}")
        lines.append(f"  Rendered pages: {report.get('rendered_pages', 0)}")
        lines.append(f"  Manual browser enabled: {report.get('manual_browser_session_enabled', False)}")
        if report.get("manual_browser_session_enabled"):
            lines.append(
                f"  Manual browser active for {report.get('manual_browser_seconds', 0)}s "
                f"(window cap {report.get('manual_browser_window_seconds', 0)}s); "
                "cookie/localStorage state is in-memory only"
            )
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

    def _import_har_file(self):
        """Import sanitized same-host traffic metadata from a browser or Burp HAR export."""
        from urllib.parse import urlparse
        from recon.har_import import load_har_file, merge_har_into_report

        target = self.url_input.text().strip()
        parsed_target = urlparse(target)
        if parsed_target.scheme.lower() not in {"http", "https"} or not parsed_target.hostname:
            QMessageBox.warning(self, "Invalid target", "Enter a full HTTP(S) target before importing a HAR file.")
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Import browser / Burp HAR", "", "HAR / JSON files (*.har *.json);;All files (*)"
        )
        if not path:
            return
        existing_target = str((self.recon_report or {}).get("target") or "").strip()
        existing_host = (urlparse(existing_target).hostname or "").lower()
        incoming_host = (parsed_target.hostname or "").lower()
        if existing_host and existing_host != incoming_host:
            answer = QMessageBox.question(
                self, "Replace current report?",
                f"The current report is for {existing_host}, while the selected target is {incoming_host}. "
                "Importing into a different target would mix unrelated findings. Reset the current report and import only this HAR?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
            self.recon_report = {}

        try:
            imported = load_har_file(path, target)
            base_report = dict(self.recon_report or {})
            base_report.setdefault("target", target)
            base_report.setdefault("pages", [])
            base_report.setdefault("filtered_pages", [])
            base_report.setdefault("endpoint_inventory", [])
            base_report.setdefault("endpoints", [])
            base_report.setdefault("parameters", [])
            base_report.setdefault("network_observations", [])
            base_report.setdefault("cookie_map", [])
            base_report.setdefault("subdomains", [])
            base_report.setdefault("passive_subdomains", [])
            base_report.setdefault("subfinder_subdomains", [])
            base_report.setdefault("emails", [])
            base_report.setdefault("forms", [])
            base_report.setdefault("header_audits", [])
            base_report.setdefault("wordlist_results", [])
            base_report.setdefault("wordlist_hits", [])
            base_report.setdefault("related_findings", [])
            base_report.setdefault("history_diff", {})
            base_report.setdefault("recent_scans", [])
            base_report.setdefault("similarity", {})
            merged = merge_har_into_report(
                base_report,
                imported.get("network_observations", []),
                imported.get("cookie_map", []),
                [imported.get("summary", {})],
            )
        except (OSError, ValueError, TypeError) as exc:
            QMessageBox.warning(self, "HAR import failed", f"{type(exc).__name__}: {exc}")
            return

        self.recon_report = merged
        self._refresh_report_filters()
        self._rebuild_table_from_filtered(self.recon_report.get("filtered_pages", []), "")
        self._populate_endpoint_parameter_findings(self.recon_report)
        self._populate_network_cookie_tables(self.recon_report)
        self._populate_subdomain_table(self.recon_report)
        self._render_recon(self.recon_report)
        self._render_similarity(self.recon_report.get("similarity", {}))
        self._populate_history(self.recon_report.get("recent_scans", []))
        self.tabs.setTabText(
            self.tabs.indexOf(self.endpoint_table),
            f"Endpoints ({len(self.recon_report.get('endpoint_inventory', []))})",
        )
        self.tabs.setTabText(
            self.tabs.indexOf(self.network_table),
            f"Network Requests ({len(self.recon_report.get('network_observations', []))})",
        )
        self.tabs.setTabText(
            self.tabs.indexOf(self.cookie_table),
            f"Cookie Map ({len(self.recon_report.get('cookie_map', []))})",
        )
        self.tabs.setTabText(
            self.tabs.indexOf(self.parameter_table),
            f"Parameters ({len(self.recon_report.get('parameters', []))})",
        )
        self.export_btn.setEnabled(True)
        self.export_txt_btn.setEnabled(True)
        self.export_csv_btn.setEnabled(True)
        summary = imported.get("summary", {})
        self.status_label.setText("HAR IMPORTED")
        self._append_log(
            f"[HAR] Imported {summary.get('entries_imported', 0)} in-scope entries "
            f"({summary.get('unique_requests', 0)} unique request records, "
            f"{summary.get('cookie_metadata_count', 0)} cookie metadata records)."
        )
        for warning in summary.get("warnings", []) or []:
            self._append_log("[HAR] Warning: " + str(warning))
        self.tabs.setCurrentWidget(self.network_table)

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
