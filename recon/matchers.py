"""Matcher/Filter engine inspired by vyre/projectdiscovery httpx."""


class MatcherFilter:
    def __init__(
        self,
        match_status=None,
        match_length=None,
        match_words=None,
        filter_status=None,
        filter_length=None,
        filter_words=None,
    ):
        self.match_status = self._parse(match_status)
        self.match_length = self._parse(match_length)
        self.match_words = self._parse(match_words)
        self.filter_status = self._parse(filter_status)
        self.filter_length = self._parse(filter_length)
        self.filter_words = self._parse(filter_words)

    @staticmethod
    def _parse(val):
        if val is None:
            return None
        if isinstance(val, (list, set, tuple)):
            try:
                return {int(x) for x in val}
            except (TypeError, ValueError):
                return None
        s = str(val).strip()
        if not s:
            return None
        try:
            return {int(x.strip()) for x in s.split(",") if x.strip()}
        except ValueError:
            return None

    def is_empty(self) -> bool:
        return not any([
            self.match_status, self.match_length, self.match_words,
            self.filter_status, self.filter_length, self.filter_words,
        ])

    def matches(self, result) -> bool:
        if self.match_status is not None:
            if result.status not in self.match_status:
                return False
        if self.match_length is not None:
            if result.content_length not in self.match_length:
                return False
        if self.match_words is not None:
            if result.word_count not in self.match_words:
                return False

        if self.filter_status is not None:
            if result.status in self.filter_status:
                return False
        if self.filter_length is not None:
            if result.content_length in self.filter_length:
                return False
        if self.filter_words is not None:
            if result.word_count in self.filter_words:
                return False

        return True

    def describe(self) -> str:
        parts = []
        if self.match_status:
            parts.append(f"match-status={sorted(self.match_status)}")
        if self.match_length:
            parts.append(f"match-length={sorted(self.match_length)}")
        if self.match_words:
            parts.append(f"match-words={sorted(self.match_words)}")
        if self.filter_status:
            parts.append(f"filter-status={sorted(self.filter_status)}")
        if self.filter_length:
            parts.append(f"filter-length={sorted(self.filter_length)}")
        if self.filter_words:
            parts.append(f"filter-words={sorted(self.filter_words)}")
        return " | ".join(parts) if parts else "(no filters)"
