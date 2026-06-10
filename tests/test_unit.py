"""Unit tests for helper functions (no Flask app required)."""

import pytest

from dserver_signed_url_plugin import (
    _extract_base_uri,
    _rewrite_url,
    _rewrite_urls_dict,
)
from dserver_signed_url_plugin.config import Config


def test_extract_base_uri():
    assert _extract_base_uri("s3://bucket/uuid-1") == "s3://bucket"
    assert _extract_base_uri("s3://bucket/prefix/uuid-1") == "s3://bucket/prefix"


@pytest.mark.parametrize("config,url,expected", [
    # url-style internal|external
    ("http://minio:9000|http://localhost:9000",
     "http://minio:9000/b/k?sig=x", "http://localhost:9000/b/k?sig=x"),
    # host:port style
    ("minio:9000|localhost:9000",
     "http://minio:9000/b/k", "http://localhost:9000/b/k"),
    # no config: pass through
    (None, "http://minio:9000/b/k", "http://minio:9000/b/k"),
    # invalid config (no separator): pass through, warn
    ("http://minio:9000:http://localhost:9000",
     "http://minio:9000/b/k", "http://minio:9000/b/k"),
])
def test_rewrite_url(monkeypatch, config, url, expected):
    monkeypatch.setattr(Config, "SIGNED_URL_HOST_REWRITE", config)
    assert _rewrite_url(url) == expected


def test_rewrite_urls_dict_recurses(monkeypatch):
    monkeypatch.setattr(
        Config, "SIGNED_URL_HOST_REWRITE",
        "http://minio:9000|http://localhost:9000")
    urls = {
        "readme_url": "http://minio:9000/b/README.yml",
        "item_urls": {"id1": "http://minio:9000/b/id1"},
        "tags": ["science"],
        "expiry_seconds": 3600,
        "headers": {"Content-MD5": "AAA="},  # must not be mangled
    }
    result = _rewrite_urls_dict(urls)
    assert result["readme_url"].startswith("http://localhost:9000")
    assert result["item_urls"]["id1"].startswith("http://localhost:9000")
    assert result["tags"] == ["science"]
    assert result["expiry_seconds"] == 3600
    assert result["headers"] == {"Content-MD5": "AAA="}
