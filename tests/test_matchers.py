from recon.matchers import MatcherFilter


class FakeResult:
    def __init__(self, status=200, word_count=100, content_length=1000):
        self.status = status
        self.word_count = word_count
        self.content_length = content_length


def test_match_status():
    m = MatcherFilter(match_status="200,301")
    assert m.matches(FakeResult(status=200))
    assert m.matches(FakeResult(status=301))
    assert not m.matches(FakeResult(status=404))


def test_filter_status():
    m = MatcherFilter(filter_status="404,500")
    assert m.matches(FakeResult(status=200))
    assert not m.matches(FakeResult(status=404))
    assert not m.matches(FakeResult(status=500))


def test_match_words():
    m = MatcherFilter(match_words="100,250")
    assert m.matches(FakeResult(word_count=100))
    assert not m.matches(FakeResult(word_count=101))


def test_combined():
    m = MatcherFilter(match_status="200", filter_words="0,1,2")
    assert m.matches(FakeResult(status=200, word_count=100))
    assert not m.matches(FakeResult(status=200, word_count=1))
    assert not m.matches(FakeResult(status=404, word_count=100))


def test_empty():
    m = MatcherFilter()
    assert m.is_empty()
    assert m.matches(FakeResult(status=500, word_count=0, content_length=0))
