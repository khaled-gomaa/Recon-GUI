"""Detect duplicate / similar pages."""
from collections import defaultdict
from urllib.parse import urlparse
import re


class SimilarityDetector:
    def __init__(self, word_count_tolerance: int = 5, min_word_count: int = 5):
        self.word_count_tolerance = word_count_tolerance
        self.min_word_count = min_word_count

    def analyze(self, results: list) -> dict:
        return {
            "exact_duplicates": self._find_exact_duplicates(results),
            "soft_404_candidates": self._find_soft_404s(results),
            "same_path_variants": self._find_path_variants(results),
            "redirect_duplicates": self._find_redirect_duplicates(results),
        }

    def _find_exact_duplicates(self, results) -> list:
        groups = defaultdict(list)
        for r in results:
            if r.content_hash:
                groups[r.content_hash].append(r.url)
        return [
            {"hash": h, "urls": sorted(urls)}
            for h, urls in groups.items() if len(urls) > 1
        ]

    def _find_soft_404s(self, results) -> list:
        buckets = defaultdict(list)
        for r in results:
            if r.status == 200 and self.min_word_count <= r.word_count < 200:
                key = (r.word_count // self.word_count_tolerance) * self.word_count_tolerance
                buckets[key].append({
                    "url": r.url,
                    "word_count": r.word_count,
                    "title": r.title,
                    "text_hash": r.text_hash,
                })
        out = []
        for bucket, pages in buckets.items():
            if len(pages) < 3:
                continue
            unique = {p["text_hash"] for p in pages}
            out.append({
                "word_count_bucket": bucket,
                "count": len(pages),
                "identical_content": len(unique) == 1,
                "pages": sorted(pages, key=lambda x: x["url"]),
            })
        return sorted(out, key=lambda x: -x["count"])

    def _find_path_variants(self, results) -> list:
        def normalize(path: str) -> str:
            path = re.sub(r"/\d+", "/{n}", path)
            path = re.sub(r"/[0-9a-f]{8,}", "/{hex}", path)
            return path.rstrip("/") or "/"

        groups = defaultdict(list)
        for r in results:
            parsed = urlparse(r.url)
            groups[normalize(parsed.path)].append({
                "url": r.url,
                "status": r.status,
                "word_count": r.word_count,
                "title": r.title,
                "text_hash": r.text_hash,
            })
        out = []
        for prefix, pages in groups.items():
            if len(pages) < 2:
                continue
            unique = {p["text_hash"] for p in pages}
            wcs = {p["word_count"] for p in pages}
            out.append({
                "path_pattern": prefix,
                "count": len(pages),
                "unique_contents": len(unique),
                "identical_content": len(unique) == 1,
                "word_count_range": [min(wcs), max(wcs)],
                "pages": sorted(pages, key=lambda x: x["url"]),
            })
        return sorted(out, key=lambda x: -x["count"])

    def _find_redirect_duplicates(self, results) -> list:
        groups = defaultdict(list)
        for r in results:
            if r.final_url and r.final_url != r.url:
                groups[r.final_url].append(r.url)
        return [
            {"final_url": f, "sources": sorted(s)}
            for f, s in groups.items() if s
        ]
