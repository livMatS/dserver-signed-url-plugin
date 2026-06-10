"""Endpoint tests for GET /signed-urls/dataset and /signed-urls/item."""

from urllib.parse import quote

import pytest

import dtoolcore

import dserver_signed_url_plugin as plugin

from .conftest import (
    DATASET_URI,
    UUID,
    FakeDataset,
    auth_header,
)

DATASET_ROUTE = f"/signed-urls/dataset/{quote(DATASET_URI, safe='')}"


@pytest.fixture
def read_env(monkeypatch):
    state = {"uri_exists": True, "dataset": FakeDataset(DATASET_URI, UUID)}
    monkeypatch.setattr(
        dtoolcore.DataSet, "from_uri",
        staticmethod(lambda uri: state["dataset"]))
    monkeypatch.setattr(
        plugin, "dataset_uri_exists", lambda uri: state["uri_exists"])
    return state


def test_read_requires_search_permission(client, dopey_token, read_env):
    response = client.get(DATASET_ROUTE, headers=auth_header(dopey_token))
    assert response.status_code == 403


def test_read_404_when_not_registered(client, sleepy_token, read_env):
    read_env["uri_exists"] = False
    response = client.get(DATASET_ROUTE, headers=auth_header(sleepy_token))
    assert response.status_code == 404


def test_read_search_permission_sufficient(client, sleepy_token, read_env):
    response = client.get(DATASET_ROUTE, headers=auth_header(sleepy_token))
    assert response.status_code == 200
    data = response.get_json()
    assert data["uri"] == DATASET_URI
    assert "readme_url" in data
    assert "manifest_url" in data
    assert data["item_urls"] == {"id1": "http://minio:9000/b/id1?sig=r"}
    assert "expiry_timestamp" in data


def test_read_applies_host_rewrite(client, sleepy_token, read_env,
                                   monkeypatch):
    from dserver_signed_url_plugin.config import Config
    monkeypatch.setattr(
        Config, "SIGNED_URL_HOST_REWRITE",
        "http://minio:9000|http://localhost:9000")
    response = client.get(DATASET_ROUTE, headers=auth_header(sleepy_token))
    assert response.status_code == 200
    data = response.get_json()
    assert data["readme_url"].startswith("http://localhost:9000")
    assert data["item_urls"]["id1"].startswith("http://localhost:9000")


def test_read_501_when_broker_cannot_sign(client, sleepy_token, read_env):
    class NoSigningBroker:
        pass

    read_env["dataset"]._storage_broker = NoSigningBroker()
    response = client.get(DATASET_ROUTE, headers=auth_header(sleepy_token))
    assert response.status_code == 501
