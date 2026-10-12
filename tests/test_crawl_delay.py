from crawler.engine import CrawlEngine


def test_wildcard_crawl_delay_is_respected():
    robots = "User-agent: *\nDisallow: /private\nCrawl-delay: 2.5\n"
    assert CrawlEngine._parse_crawl_delay(robots) == 2.5


def test_specific_recon_user_agent_delay_takes_precedence():
    robots = """
    User-agent: *
    Crawl-delay: 1
    User-agent: Recon-GUI
    Crawl-delay: 4
    """
    assert CrawlEngine._parse_crawl_delay(robots) == 4


def test_unrelated_agent_delay_does_not_override_wildcard():
    robots = """
    User-agent: ExampleBot
    Crawl-delay: 10
    User-agent: *
    Crawl-delay: 2
    """
    assert CrawlEngine._parse_crawl_delay(robots) == 2


def test_missing_or_invalid_crawl_delay_is_zero():
    assert CrawlEngine._parse_crawl_delay("User-agent: *\nDisallow: /") == 0
    assert CrawlEngine._parse_crawl_delay("User-agent: *\nCrawl-delay: no") == 0
