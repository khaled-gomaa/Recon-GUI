"""Matcher/filter engine inspired by HTTP probing tools.

Accepted syntax is comma-separated values, numeric ranges (e.g. 200-299),
and HTTP status classes for status fields (e.g. 2xx, 3xx, 5xx).
"""


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
        self.match_status = self._parse(match_status, allow_status_classes=True, field="match status")
        self.match_length = self._parse(match_length, field="match length")
        self.match_words = self._parse(match_words, field="match words")
        self.filter_status = self._parse(filter_status, allow_status_classes=True, field="filter status")
        self.filter_length = self._parse(filter_length, field="filter length")
        self.filter_words = self._parse(filter_words, field="filter words")

    @staticmethod
    def _parse(value, allow_status_classes=False, field="value"):
        if value is None:
            return None
        if isinstance(value, str):
            raw_tokens = [token.strip().lower() for token in value.split(",") if token.strip()]
        elif isinstance(value, (list, set, tuple)):
            raw_tokens = [str(token).strip().lower() for token in value if str(token).strip()]
        elif isinstance(value, int):
            raw_tokens = [str(value)]
        else:
            raise ValueError(f"Invalid {field}: expected comma-separated numbers or ranges")

        if not raw_tokens:
            return None

        ranges = []
        for token in raw_tokens:
            if allow_status_classes and len(token) == 3 and token[0] in "12345" and token[1:] == "xx":
                low = int(token[0]) * 100
                ranges.append((low, low + 99))
                continue
            if "-" in token:
                parts = token.split("-", 1)
                if len(parts) != 2 or not all(part.isdigit() for part in parts):
                    raise ValueError(f"Invalid {field} token '{token}'. Use values like 200,301 or ranges like 200-299.")
                low, high = map(int, parts)
                if low > high:
                    raise ValueError(f"Invalid {field} range '{token}': start must not exceed end")
                ranges.append((low, high))
                continue
            if not token.isdigit():
                if allow_status_classes:
                    hint = " (status classes such as 2xx are also allowed)"
                else:
                    hint = ""
                raise ValueError(f"Invalid {field} token '{token}'. Use numbers or ranges{hint}.")
            number = int(token)
            ranges.append((number, number))

        return ranges or None

    @staticmethod
    def _contains(conditions, value):
        return conditions is not None and any(low <= value <= high for low, high in conditions)

    @staticmethod
    def _format(conditions):
        if not conditions:
            return None
        return ",".join(str(low) if low == high else f"{low}-{high}" for low, high in conditions)

    def is_empty(self) -> bool:
        return not any((
            self.match_status, self.match_length, self.match_words,
            self.filter_status, self.filter_length, self.filter_words,
        ))

    def matches(self, result) -> bool:
        if self.match_status is not None and not self._contains(self.match_status, result.status):
            return False
        if self.match_length is not None and not self._contains(self.match_length, result.content_length):
            return False
        if self.match_words is not None and not self._contains(self.match_words, result.word_count):
            return False

        if self.filter_status is not None and self._contains(self.filter_status, result.status):
            return False
        if self.filter_length is not None and self._contains(self.filter_length, result.content_length):
            return False
        if self.filter_words is not None and self._contains(self.filter_words, result.word_count):
            return False
        return True

    def describe(self) -> str:
        parts = []
        for name, conditions in (
            ("match-status", self.match_status),
            ("match-length", self.match_length),
            ("match-words", self.match_words),
            ("filter-status", self.filter_status),
            ("filter-length", self.filter_length),
            ("filter-words", self.filter_words),
        ):
            value = self._format(conditions)
            if value:
                parts.append(f"{name}={value}")
        return " | ".join(parts) if parts else "(no filters)"
