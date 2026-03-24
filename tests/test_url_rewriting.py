"""Tests for URL rewriting and base URI extraction utilities."""

import pytest
from dserver_signed_url_plugin import _rewrite_url, _rewrite_urls_dict, _extract_base_uri
from dserver_signed_url_plugin import config as plugin_config


@pytest.fixture(autouse=True)
def reset_host_rewrite():
    """Reset SIGNED_URL_HOST_REWRITE to None after each test."""
    original = plugin_config.Config.SIGNED_URL_HOST_REWRITE
    yield
    plugin_config.Config.SIGNED_URL_HOST_REWRITE = original


class TestExtractBaseUri:
    def test_simple_s3_uri(self):
        uri = "s3://mybucket/dataset-uuid"
        assert _extract_base_uri(uri) == "s3://mybucket"

    def test_nested_s3_uri(self):
        uri = "s3://mybucket/prefix/subprefix/dataset-uuid"
        assert _extract_base_uri(uri) == "s3://mybucket/prefix/subprefix"

    def test_local_uri(self):
        uri = "/home/user/data/my-dataset-uuid"
        assert _extract_base_uri(uri) == "/home/user/data"


class TestRewriteUrl:
    def test_no_rewrite_when_not_configured(self):
        plugin_config.Config.SIGNED_URL_HOST_REWRITE = None
        url = "http://minio:9000/bucket/file"
        assert _rewrite_url(url) == url

    def test_no_rewrite_when_empty_string(self):
        plugin_config.Config.SIGNED_URL_HOST_REWRITE = ""
        url = "http://minio:9000/bucket/file"
        assert _rewrite_url(url) == url

    def test_simple_host_rewrite(self):
        plugin_config.Config.SIGNED_URL_HOST_REWRITE = \
            "http://minio:9000:http://localhost:9000"
        url = "http://minio:9000/bucket/file?X-Amz-Signature=abc123"
        result = _rewrite_url(url)
        assert "localhost:9000" in result
        assert "minio" not in result

    def test_non_matching_url_unchanged(self):
        plugin_config.Config.SIGNED_URL_HOST_REWRITE = \
            "http://minio:9000:http://localhost:9000"
        url = "http://other-host:9000/bucket/file"
        result = _rewrite_url(url)
        assert result == url

    def test_rewrite_preserves_path_and_query(self):
        plugin_config.Config.SIGNED_URL_HOST_REWRITE = \
            "http://minio:9000:http://localhost:9000"
        url = "http://minio:9000/bucket/path/to/file?param=value&other=123"
        result = _rewrite_url(url)
        assert "/bucket/path/to/file" in result
        assert "param=value" in result


class TestRewriteUrlsDict:
    def test_rewrites_url_string_values(self):
        plugin_config.Config.SIGNED_URL_HOST_REWRITE = \
            "http://minio:9000:http://localhost:9000"
        d = {"readme": "http://minio:9000/bucket/readme.yml"}
        result = _rewrite_urls_dict(d)
        assert "localhost:9000" in result["readme"]
        assert "minio" not in result["readme"]

    def test_leaves_non_url_strings_unchanged(self):
        plugin_config.Config.SIGNED_URL_HOST_REWRITE = \
            "http://minio:9000:http://localhost:9000"
        d = {"name": "my-dataset", "uuid": "abc-123"}
        result = _rewrite_urls_dict(d)
        assert result == d

    def test_handles_nested_dicts(self):
        plugin_config.Config.SIGNED_URL_HOST_REWRITE = \
            "http://minio:9000:http://localhost:9000"
        d = {"items": {"id1": {"url": "http://minio:9000/data/id1"}}}
        result = _rewrite_urls_dict(d)
        assert "localhost:9000" in result["items"]["id1"]["url"]

    def test_handles_list_of_urls(self):
        plugin_config.Config.SIGNED_URL_HOST_REWRITE = \
            "http://minio:9000:http://localhost:9000"
        d = {"urls": ["http://minio:9000/a", "http://minio:9000/b"]}
        result = _rewrite_urls_dict(d)
        for url in result["urls"]:
            assert "localhost:9000" in url

    def test_handles_mixed_list(self):
        plugin_config.Config.SIGNED_URL_HOST_REWRITE = \
            "http://minio:9000:http://localhost:9000"
        d = {"items": ["http://minio:9000/a", "not-a-url", 42]}
        result = _rewrite_urls_dict(d)
        assert "localhost:9000" in result["items"][0]
        assert result["items"][1] == "not-a-url"
        assert result["items"][2] == 42

    def test_returns_new_dict_not_mutating(self):
        plugin_config.Config.SIGNED_URL_HOST_REWRITE = \
            "http://minio:9000:http://localhost:9000"
        original = {"url": "http://minio:9000/file"}
        result = _rewrite_urls_dict(original)
        # original should be unchanged
        assert original["url"] == "http://minio:9000/file"
        assert result["url"] != original["url"]
