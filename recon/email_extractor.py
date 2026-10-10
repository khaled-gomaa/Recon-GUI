"""Extract email addresses from raw HTML/text."""
import re

EMAIL_RE = re.compile(
    r"(?<!@)\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]{2,}\b(?!@)"
)


class EmailExtractor:
    @staticmethod
    def extract(text: str) -> set:
        found = set(EMAIL_RE.findall(text))
        return {
            e for e in found
            if not e.lower().endswith((".png", ".jpg", ".gif", ".svg", ".css", ".js"))
            and "example." not in e.lower()
            and not e.lower().startswith("no-reply")
        }
