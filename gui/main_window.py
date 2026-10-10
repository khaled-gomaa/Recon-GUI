"""Main application window."""
import json
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QSpinBox, QPushButton, QTextEdit, QTableWidget,
    QTableWidgetItem, QTabWidget, QFileDialog, QMessageBox,
)
from PySide6.QtGui import QColor
from gui.worker import CrawlWorker
from recon.matchers import MatcherFilter


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Recon Crawler v2 - Desktop Website Reconnaissance")
        self.resize(1300, 800)
        self.worker = None
        self.recon_report = {}
        self._build_ui()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        # Row 1
        input_row = QHBoxLayout()
        input_row.addWidget(QLabel("Target URL:"))
        self.url_input = QLineEdit("https://example.com")
        input_row.addWidget(self.url_input, stretch=1)

        input_row.addWidget(QLabel("Depth:"))
        self.depth_spin = QSpinBox()
        self.depth_spin.setRange(1, 5)
        self.depth_spin.setValue(2)
        input_row.addWidget(self.depth_spin)

        input_row.addWidget(QLabel("Max pages:"))
        self.pages_spin = QSpinBox()
        self.pages_spin.setRange(10, 5000)
        self.pages_spin.setValue(200)
        input_row.addWidget(self.pages_spin)

        input_row.addWidget(QLabel("Concurrency:"))
        self.conc_spin = QSpinBox()
        self.conc_spin.setRange(1, 500)
        self.conc_spin.setValue(50)
        input_row.addWidget(self.conc_spin)
        root.addLayout(input_row)

        # Row 2
        wl_row = QHBoxLayout()
        wl_row.addWidget(QLabel("Wordlist:"))
        self.wordlist_input = QLineEdit()
        self.wordlist_input.setPlaceholderText("(optional) e.g. wordlists/common.txt")
        wl_row.addWidget(self.wordlist_input, stretch=1)
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self._pick_wordlist)
        wl_row.addWidget(browse_btn)

        self.start_btn = QPushButton("Start Crawl")
        self.start_btn.clicked.connect(self._start_crawl)
        wl_row.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_crawl)
        wl_row.addWidget(self.stop_btn)
        root.addLayout(wl_row)

        # Row 3 - Matchers/Filters
        mf_row = QHBoxLayout()

        mf_row.addWidget(QLabel("Match Status:"))
        self.match_status = QLineEdit()
        self.match_status.setPlaceholderText("200,301,302")
        self.match_status.setMaximumWidth(140)
        mf_row.addWidget(self.match_status)

        mf_row.addWidget(QLabel("Match Words:"))
        self.match_words = QLineEdit()
        self.match_words.setPlaceholderText("100,250,500")
        self.match_words.setMaximumWidth(140)
        mf_row.addWidget(self.match_words)

        mf_row.addWidget(QLabel("Match Length:"))
        self.match_length = QLineEdit()
        self.match_length.setPlaceholderText("1024,2048")
        self.match_length.setMaximumWidth(140)
        mf_row.addWidget(self.match_length)

        mf_row.addWidget(QLabel("Filter Status:"))
        self.filter_status = QLineEdit()
        self.filter_status.setPlaceholderText("404,500")
        self.filter_status.setMaximumWidth(120)
        mf_row.addWidget(self.filter_status)

        mf_row.addWidget(QLabel("Filter Words:"))
        self.filter_words = QLineEdit()
        self.filter_words.setPlaceholderText("0,1,2")
        self.filter_words.setMaximumWidth(120)
        mf_row.addWidget(self.filter_words)

        mf_row.addStretch()
        root.addLayout(mf_row)

        # Tabs
        self.tabs = QTabWidget()
        root.addWidget(self.tabs, stretch=1)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.tabs.addTab(self.log_view, "Log")

        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels([
            "URL", "Status", "Chain", "Final URL",
            "Words", "Title", "Hash", "Favicon",
        ])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 300)
        self.table.setColumnWidth(2, 130)
        self.table.setColumnWidth(3, 200)
        self.tabs.addTab(self.table, "Pages (filtered)")

        self.similarity_view = QTextEdit()
        self.similarity_view.setReadOnly(True)
        self.tabs.addTab(self.similarity_view, "Similar Pages")

        self.recon_view = QTextEdit()
        self.recon_view.setReadOnly(True)
        self.tabs.addTab(self.recon_view, "Recon Findings")

        # Bottom
        bottom = QHBoxLayout()
        self.export_btn = QPushButton("Export Recon JSON")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self._export_json)
        bottom.addWidget(self.export_btn)
        bottom.addStretch()
        self.status_label = QLabel("Ready.")
        bottom.addWidget(self.status_label)
        root.addLayout(bottom)

    def _pick_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Wordlist", "", "Text Files (*.txt);;All Files (*)"
        )
        if path:
            self.wordlist_input.setText(path)

    def _build_matcher(self) -> MatcherFilter:
        return MatcherFilter(
            match_status=self.match_status.text().strip(),
            match_length=self.match_length.text().strip(),
            match_words=self.match_words.text().strip(),
            filter_status=self.filter_status.text().strip(),
            filter_length=None,
            filter_words=self.filter_words.text().strip(),
        )

    def _start_crawl(self):
        url = self.url_input.text().strip()
        if not url.startswith(("http://", "https://")):
            QMessageBox.warning(self, "Invalid URL",
                                "URL must start with http:// or https://")
            return

        self.log_view.clear()
        self.table.setRowCount(0)
        self.recon_view.clear()
        self.similarity_view.clear()
        self.recon_report = {}
        self.export_btn.setEnabled(False)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Crawling...")

        self.worker = CrawlWorker(
            url=url,
            max_depth=self.depth_spin.value(),
            max_pages=self.pages_spin.value(),
            concurrency=self.conc_spin.value(),
            wordlist_path=self.wordlist_input.text().strip() or None,
            matcher=self._build_matcher(),
        )
        self.worker.log_message.connect(self._append_log)
        self.worker.page_crawled.connect(self._on_page_crawled)
        self.worker.finished.connect(self._on_finished)
        self.worker.error.connect(self._on_error)
        self.worker.start()

    def _stop_crawl(self):
        if self.worker:
            self.worker.terminate()
            self._append_log("[Stopped by user]")
        self._reset_buttons()

    def _append_log(self, msg: str):
        self.log_view.append(msg)

    def _on_page_crawled(self, result):
        row = self.table.rowCount()
        self.table.insertRow(row)

        if result.redirect_chain:
            chain = " -> ".join(str(c["status"]) for c in result.redirect_chain)
            chain += f" -> {result.status}"
        else:
            chain = "--"
        final_url = result.final_url if result.final_url != result.url else "--"

        self.table.setItem(row, 0, QTableWidgetItem(result.url))
        self.table.setItem(row, 1, QTableWidgetItem(str(result.status)))
        self.table.setItem(row, 2, QTableWidgetItem(chain))
        self.table.setItem(row, 3, QTableWidgetItem(final_url))
        self.table.setItem(row, 4, QTableWidgetItem(str(result.word_count)))
        self.table.setItem(row, 5, QTableWidgetItem(result.title))
        self.table.setItem(row, 6, QTableWidgetItem(result.content_hash))
        self.table.setItem(row, 7, QTableWidgetItem("--"))

        color = None
        if result.status == 200:
            color = "#1e7e34"
        elif result.status in (301, 302, 307, 308):
            color = "#b8860b"
        elif result.status in (401, 403):
            color = "#c82333"
        elif result.status == 404:
            color = "#6c757d"
        if color:
            for col in (1, 2):
                item = self.table.item(row, col)
                if item:
                    item.setForeground(QColor(color))

    def _rebuild_table_from_filtered(self, filtered, favicon_hash):
        self.table.setRowCount(0)
        for result in filtered:
            row = self.table.rowCount()
            self.table.insertRow(row)

            if result["redirect_chain"]:
                chain = " -> ".join(
                    str(c["status"]) for c in result["redirect_chain"]
                )
                chain += f" -> {result['status']}"
            else:
                chain = "--"
            final_url = (result["final_url"]
                         if result["final_url"] != result["url"] else "--")

            self.table.setItem(row, 0, QTableWidgetItem(result["url"]))
            self.table.setItem(row, 1, QTableWidgetItem(str(result["status"])))
            self.table.setItem(row, 2, QTableWidgetItem(chain))
            self.table.setItem(row, 3, QTableWidgetItem(final_url))
            self.table.setItem(row, 4, QTableWidgetItem(str(result["word_count"])))
            self.table.setItem(row, 5, QTableWidgetItem(result["title"]))
            self.table.setItem(row, 6, QTableWidgetItem(result["content_hash"]))
            self.table.setItem(row, 7, QTableWidgetItem(favicon_hash or "--"))

            color = None
            if result["status"] == 200:
                color = "#1e7e34"
            elif result["status"] in (301, 302, 307, 308):
                color = "#b8860b"
            elif result["status"] in (401, 403):
                color = "#c82333"
            elif result["status"] == 404:
                color = "#6c757d"
            if color:
                for col in (1, 2):
                    item = self.table.item(row, col)
                    if item:
                        item.setForeground(QColor(color))

    def _on_finished(self, report: dict):
        self.recon_report = report
        favicon = report.get("favicon_hash", "")
        filtered = report.get("filtered_pages", [])
        self._rebuild_table_from_filtered(filtered, favicon)
        self._render_recon(report)
        self._render_similarity(report.get("similarity", {}))
        self.export_btn.setEnabled(True)
        self._reset_buttons()

        sim = report.get("similarity", {})
        kept = len(filtered)
        total = len(report.get("pages", []))
        matcher_note = ""
        if report.get("matcher_applied"):
            matcher_note = f" | matched {kept}/{total}"
        self.status_label.setText(
            f"Done -- {total} pages crawled{matcher_note}, "
            f"favicon={favicon or 'n/a'} | "
            f"{len(sim.get('exact_duplicates', []))} dup groups, "
            f"{len(sim.get('soft_404_candidates', []))} soft-404s."
        )

    def _on_error(self, msg: str):
        self._append_log(f"[FATAL] {msg}")
        self._reset_buttons()
        self.status_label.setText("Error.")

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
                        "js_files", "source_maps"):
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

    def _export_json(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Recon JSON", "recon_report.json", "JSON (*.json)"
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.recon_report, f, indent=2, ensure_ascii=False)
            self.status_label.setText(f"Exported: {path}")
