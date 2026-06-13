"""Endpoint tests for POST /signed-urls/upload and upload-complete."""

from urllib.parse import quote

import pytest

from botocore.exceptions import ClientError

import dtoolcore

import dserver_signed_url_plugin as plugin
from dserver_signed_url_plugin.sql_models import PendingUpload

from .conftest import (
    BASE_URI,
    DATASET_URI,
    UUID,
    FakeDataset,
    FakeProtoDataset,
    auth_header,
    upload_request_body,
)

UPLOAD_ROUTE = f"/signed-urls/upload/{quote(BASE_URI, safe='')}"


@pytest.fixture
def upload_env(monkeypatch):
    """Patch dtoolcore and dservercore touchpoints for the upload path."""
    state = {"proto": None, "uri_exists": False}

    def fake_generate_proto_dataset(admin_metadata, base_uri, **kw):
        state["proto"] = FakeProtoDataset(
            f"{base_uri}/{admin_metadata['uuid']}", admin_metadata["uuid"])
        state["admin_metadata"] = admin_metadata
        return state["proto"]

    def fake_proto_from_uri(uri):
        if state.get("resumable_proto"):
            return state["resumable_proto"]
        raise dtoolcore.DtoolCoreTypeError("no proto dataset")

    monkeypatch.setattr(
        dtoolcore, "generate_proto_dataset", fake_generate_proto_dataset)
    monkeypatch.setattr(
        dtoolcore.ProtoDataSet, "from_uri", staticmethod(fake_proto_from_uri))
    monkeypatch.setattr(
        plugin, "dataset_uri_exists", lambda uri: state["uri_exists"])
    return state


def test_upload_requires_register_permission(client, sleepy_token, upload_env):
    response = client.post(
        UPLOAD_ROUTE, json=upload_request_body(),
        headers=auth_header(sleepy_token))
    assert response.status_code == 403


def test_upload_unknown_user_403(client, dopey_token, upload_env):
    response = client.post(
        UPLOAD_ROUTE, json=upload_request_body(),
        headers=auth_header(dopey_token))
    assert response.status_code == 403


def test_upload_no_token_401(client, upload_env):
    response = client.post(UPLOAD_ROUTE, json=upload_request_body())
    assert response.status_code == 401


def test_upload_success_returns_pinned_urls(client, grumpy_token, upload_env):
    response = client.post(
        UPLOAD_ROUTE, json=upload_request_body(),
        headers=auth_header(grumpy_token))
    assert response.status_code == 200
    data = response.get_json()
    assert data["uuid"] == UUID
    assert data["uri"] == DATASET_URI

    items = data["upload_urls"]["items"]
    assert len(items) == 1
    (item,) = items.values()
    assert item["relpath"] == "data.txt"
    assert item["headers"]["Content-MD5"] == "pinned-md5-b64"
    assert item["headers"]["x-amz-meta-checksum"] == \
        "9a0364b9e99bb480dd25e1f0284c8555"

    # Proto-dataset was created with the requested name and metadata.
    proto = upload_env["proto"]
    assert proto.created
    assert upload_env["admin_metadata"]["name"] == "my-dataset"
    assert proto.tags == ["science"]
    assert proto.annotations == {"project": "test"}

    # Pending upload row recorded.
    pending = PendingUpload.query.filter_by(uuid=UUID).first()
    assert pending is not None
    assert pending.uri == DATASET_URI
    assert pending.name == "my-dataset"


def test_upload_writes_overlays_to_storage(client, grumpy_token, upload_env):
    body = upload_request_body(overlays={"quality": {"id1": "good"}})
    response = client.post(
        UPLOAD_ROUTE, json=body, headers=auth_header(grumpy_token))
    assert response.status_code == 200
    assert upload_env["proto"]._storage_broker.overlays == {
        "quality": {"id1": "good"}}


def test_upload_rejects_non_md5_hash_function(client, grumpy_token, upload_env):
    body = upload_request_body(hash_function="sha256_hexdigest")
    response = client.post(
        UPLOAD_ROUTE, json=body, headers=auth_header(grumpy_token))
    assert response.status_code == 400


def test_upload_rejects_invalid_dataset_name(client, grumpy_token, upload_env):
    body = upload_request_body(name="INVALID!!!NAME with spaces")
    response = client.post(
        UPLOAD_ROUTE, json=body, headers=auth_header(grumpy_token))
    assert response.status_code == 400


def test_upload_storage_access_denied_502(
        client, grumpy_token, upload_env, monkeypatch):
    def denied_generate_proto_dataset(admin_metadata, base_uri, **kw):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "PutObject")

    monkeypatch.setattr(
        dtoolcore, "generate_proto_dataset", denied_generate_proto_dataset)
    response = client.post(
        UPLOAD_ROUTE, json=upload_request_body(),
        headers=auth_header(grumpy_token))
    assert response.status_code == 502
    assert b"AccessDenied" in response.data


def test_upload_conflict_when_registered(client, grumpy_token, upload_env):
    upload_env["uri_exists"] = True
    response = client.post(
        UPLOAD_ROUTE, json=upload_request_body(),
        headers=auth_header(grumpy_token))
    assert response.status_code == 409


def test_upload_conflict_same_uuid_different_location(
        client, grumpy_token, upload_env):
    from dservercore import sql_db
    sql_db.session.add(PendingUpload(
        uuid=UUID, uri=f"s3://other-bucket/{UUID}",
        base_uri="s3://other-bucket", name="other", creator_username="x",
        frozen_at=1.0, manifest={"items": {}}))
    sql_db.session.commit()

    response = client.post(
        UPLOAD_ROUTE, json=upload_request_body(),
        headers=auth_header(grumpy_token))
    assert response.status_code == 409


def test_upload_resume_reuses_proto_and_updates_row(
        client, grumpy_token, upload_env):
    # First request creates proto + pending row.
    response = client.post(
        UPLOAD_ROUTE, json=upload_request_body(),
        headers=auth_header(grumpy_token))
    assert response.status_code == 200
    first_proto = upload_env["proto"]

    # Make the existing proto loadable, then retry with a new name.
    upload_env["resumable_proto"] = first_proto
    upload_env["proto"] = None
    response = client.post(
        UPLOAD_ROUTE, json=upload_request_body(name="renamed-dataset"),
        headers=auth_header(grumpy_token))
    assert response.status_code == 200

    # No second proto-dataset was created; the row was refreshed.
    assert upload_env["proto"] is None
    assert PendingUpload.query.filter_by(uuid=UUID).count() == 1
    pending = PendingUpload.query.filter_by(uuid=UUID).first()
    assert pending.name == "renamed-dataset"


class TestUploadComplete:

    ROUTE = "/signed-urls/upload-complete"

    @pytest.fixture
    def complete_env(self, monkeypatch):
        state = {"registered": [], "proto": FakeProtoDataset(DATASET_URI, UUID)}

        monkeypatch.setattr(
            dtoolcore.ProtoDataSet, "from_uri",
            staticmethod(lambda uri: state["proto"]))
        monkeypatch.setattr(
            dtoolcore.DataSet, "from_uri",
            staticmethod(lambda uri: FakeDataset(uri, UUID)))
        monkeypatch.setattr(
            plugin, "generate_dataset_info",
            lambda dataset, base_uri: {"uri": dataset.uri,
                                       "uuid": dataset.uuid,
                                       "base_uri": base_uri,
                                       "name": dataset.name})
        monkeypatch.setattr(
            plugin, "register_dataset",
            lambda info: state["registered"].append(info))
        return state

    def add_pending(self, uri=DATASET_URI):
        from dservercore import sql_db
        sql_db.session.add(PendingUpload(
            uuid=UUID, uri=uri, base_uri=uri.rsplit("/", 1)[0],
            name="my-dataset", creator_username="grumpy",
            frozen_at=1700000000.0,
            manifest={"items": {}, "hash_function": "md5sum_hexdigest"}))
        sql_db.session.commit()

    def test_requires_register_permission(self, client, sleepy_token,
                                          complete_env):
        self.add_pending()
        response = client.post(
            self.ROUTE, json={"uri": DATASET_URI},
            headers=auth_header(sleepy_token))
        assert response.status_code == 403

    def test_no_pending_400(self, client, grumpy_token, complete_env):
        response = client.post(
            self.ROUTE, json={"uri": DATASET_URI},
            headers=auth_header(grumpy_token))
        assert response.status_code == 400

    def test_uri_mismatch_409(self, client, grumpy_token, complete_env):
        # Pending upload was initiated for a different location.
        self.add_pending(uri=f"s3://other-bucket/{UUID}")
        response = client.post(
            self.ROUTE, json={"uri": DATASET_URI},
            headers=auth_header(grumpy_token))
        assert response.status_code == 409
        # The foreign pending record must not be deleted.
        assert PendingUpload.query.filter_by(uuid=UUID).count() == 1

    def test_freeze_access_denied_502(self, client, grumpy_token,
                                      complete_env):
        def denied_freeze(manifest, frozen_at=None):
            raise ClientError(
                {"Error": {"Code": "AccessDenied",
                           "Message": "Access Denied"}},
                "PutObject")

        complete_env["proto"].freeze_with_manifest = denied_freeze
        self.add_pending()
        response = client.post(
            self.ROUTE, json={"uri": DATASET_URI},
            headers=auth_header(grumpy_token))
        assert response.status_code == 502
        assert b"AccessDenied" in response.data
        # Pending record must survive so the upload can be retried.
        assert PendingUpload.query.filter_by(uuid=UUID).count() == 1

    def test_success_freezes_registers_and_cleans_up(
            self, client, grumpy_token, complete_env):
        self.add_pending()
        response = client.post(
            self.ROUTE, json={"uri": DATASET_URI},
            headers=auth_header(grumpy_token))
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "registered"
        assert data["uuid"] == UUID

        # Frozen with the stored manifest and frozen_at.
        manifest, frozen_at = complete_env["proto"].frozen_with
        assert frozen_at == 1700000000.0
        assert manifest["hash_function"] == "md5sum_hexdigest"

        # Registered in dserver and pending row removed.
        assert len(complete_env["registered"]) == 1
        assert PendingUpload.query.filter_by(uuid=UUID).count() == 0
