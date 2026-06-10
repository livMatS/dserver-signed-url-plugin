"""Test fixtures for dserver-signed-url-plugin.

Mirrors the dservercore test setup: in-memory SQLite for admin metadata,
a throwaway MongoDB database for search/retrieve (requires a MongoDB at
localhost:27017 or TEST_MONGO_URI), and canned RS256 JWTs.

Users:
- snow-white: admin
- grumpy: search + register permission on s3://snow-white
- sleepy: search permission only
- dopey: registered nowhere
"""

import random
import string
import os

import pytest

from dtoolcore.utils import generate_identifier

JWT_PUBLIC_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8LrEp0Q6l1WPsY32uOPqEjaisQScnzO/XvlhQTzj5w+hFObjiNgIaHRceYh3hZZwsRsHIkCxOY0JgUPeFP9IVXso0VptIjCPRF5yrV/+dF1rtl4eyYj/XOBvSDzbQQwqdjhHffw0TXW0f/yjGGJCYM+tw/9dmj9VilAMNTx1H76uPKUo4M3vLBQLo2tj7z1jlh4Jlw5hKBRcWQWbpWP95p71Db6gSpqReDYbx57BW19APMVketUYsXfXTztM/HWz35J9HDya3ID0Dl+pE22Wo8SZo2+ULKu/4OYVcD8DjF15WwXrcuFDypX132j+LUWOVWxCs5hdMybSDwF3ZhVBH ec2-user@ip-172-31-41-191.eu-west-1.compute.internal"  # NOQA

BASE_URI = "s3://snow-white"
UUID = "af6727bf-29c7-43dd-b42f-a5d7ede28337"
DATASET_URI = f"{BASE_URI}/{UUID}"


def random_string(size=9, prefix="test_"):
    chars = string.ascii_letters + string.digits
    return prefix + "".join(random.choice(chars) for _ in range(size))


@pytest.fixture
def grumpy_token():
    # search + register on s3://snow-white
    return "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTYyMTEwMTY0NywianRpIjoiYWFmMTc3NTQtNzc4Mi00ODAzLThlZDItODZhYmI0ZDVhYThlIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImdydW1weSIsIm5iZiI6MTYyMTEwMTY0N30.tvYTnOflEGjPM1AmDMQxE-2CAa7Je3uhq5DEQutUUGyuMHyT7phsam8l0aHGQjlCZb2X98Gs9QeQ5rXwxP5y8oteQzk26QbunW3Jpg46E1PheESURqOScLgyyiKa6aHtztb5aa5VxK2LgFB13JrQZ03GJpuDPQj7q1Lbu2Cn0JjX3YXRuF14ZkZk8ZrybnKsJ3RLKup_SUDeDx20hJFYBbnyd8jZSd5xV9eQfSrMHFhDBAnV9c8gzMXKnNR5OtVLyFWVrOB4OsP3Woy2eyXmM9G3Qljft6j_jtYcra7-7BnvIZE8JSLcTT0cH563KISFNqMxmkrWqhZaHRCRRhwsPg"  # NOQA


@pytest.fixture
def sleepy_token():
    # search-only on s3://snow-white
    return "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTYyMTEwMTcxOCwianRpIjoiMDM2YmNmZTktODg5OC00Nzg0LWIwYWQtZTRkOTczN2JjZjgxIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6InNsZWVweSIsIm5iZiI6MTYyMTEwMTcxOH0.OoHNM5l_p8n2OKz-IEondgHzUhHwXmPY0rWnXrto9WSkHEGOAL6Yqc37dancRUIzvvG2l_oK88O0eHJEFMPT0M0F-18wvCQ9wdQfiAUSiagFw4o_sUomHXu0xWjDFZ-gClUW-85qZiyKjx8gYvCYod1rehBy1B52kZ6DAd2tzQfwzI8ncgsjdsqGcOotkLisidGrqRA2jXqeJjPrwNQlHNl4OH7n7pxzzMb4_spyWEG12pjYZwa77oMDim_RjQpmo8RnNOEgenN9fGnBN3myluKY8AV7ZCat5vORzrKARWOj_-EQr6c6-9ZrxLWArEVkecB-WG6f5U8KmnUsrPq6Cg"  # NOQA


@pytest.fixture
def dopey_token():
    # registered nowhere
    return "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTYyMTEwMTY5NCwianRpIjoiZjNlOTFmNjQtZTIzZi00MWRkLThhOTAtMWUzYzkzMDlmYTM0IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRvcGV5IiwibmJmIjoxNjIxMTAxNjk0fQ.KJHiQN3MNGsfRQ_pGU0AGNSP-7-PR3oWvxUxjqtY23FPcrH3dJ3MTSVvD1kWiiEOkE-3kbq9KOg8g4OhpifBM44DbA-R5Xjuk_99Grc6TnPQMaB7W5s1k8JCs20wTW4gAM4t1ANixVQT0IW6T0OF_WeotWp-RaOkzYlMAp3KNotCNvlbj-fS-d3NEDucNjbHG_p9DgbOVLxD1jM-7GykMpLNvVeI5KZkgjvtxXvQt2sU_Dnm-J15TmknUaO6pLF--OA8AM8rZDf4p-QISsOu6uQEbxo9XSU_OHe7pzNebge54v3hd0vj5nAVqLg73myUHqOximaaObQRXk7ZOqjE4g"  # NOQA


class FakeWriteBroker:
    """Storage broker stand-in for the upload path."""

    def __init__(self, uuid):
        self.uuid = uuid
        self.data_key_prefix = f"{uuid}/data/"
        self.overlays = {}

    def get_readme_key(self):
        return f"{self.uuid}/README.yml"

    def generate_signed_write_url(self, key, expiry_seconds):
        return f"https://s3.fake/{key}?sig=write"

    def generate_signed_item_write_url(self, relpath, md5, expiry_seconds):
        identifier = generate_identifier(relpath)
        url = f"https://s3.fake/{self.data_key_prefix}{identifier}?sig=item"
        headers = {
            "Content-MD5": "pinned-md5-b64",
            "x-amz-meta-checksum": md5,
            "x-amz-meta-handle": "cGlubmVk",
        }
        return url, headers

    def put_overlay(self, overlay_name, overlay):
        self.overlays[overlay_name] = overlay


class FakeProtoDataset:
    def __init__(self, uri, uuid):
        self.uri = uri
        self.uuid = uuid
        self._storage_broker = FakeWriteBroker(uuid)
        self.created = False
        self.readme = None
        self.tags = []
        self.annotations = {}
        self.frozen_with = None

    def create(self):
        self.created = True

    def put_readme(self, content):
        self.readme = content

    def put_tag(self, tag):
        self.tags.append(tag)

    def put_annotation(self, name, value):
        self.annotations[name] = value

    def freeze_with_manifest(self, manifest, frozen_at=None):
        self.frozen_with = (manifest, frozen_at)


class FakeReadBroker:
    """Storage broker stand-in for the read path."""

    def __init__(self, uuid):
        self.data_key_prefix = f"{uuid}/data/"

    def generate_dataset_signed_urls(self, expiry_seconds):
        return {
            "admin_metadata_url": "http://minio:9000/b/dtool?sig=r",
            "manifest_url": "http://minio:9000/b/manifest.json?sig=r",
            "readme_url": "http://minio:9000/b/README.yml?sig=r",
            "item_urls": {"id1": "http://minio:9000/b/id1?sig=r"},
            "overlay_urls": {},
            "annotation_urls": {},
            "tags": ["science"],
        }


class FakeDataset:
    def __init__(self, uri, uuid, name="frozen-dataset"):
        self.uri = uri
        self.uuid = uuid
        self.name = name
        self._storage_broker = FakeReadBroker(uuid)


@pytest.fixture
def tmp_app_with_users(request):
    from flask import current_app
    from dservercore import create_app, sql_db
    from dservercore.utils import (
        register_users,
        register_base_uri,
        register_permissions,
    )

    tmp_mongo_db_name = random_string()
    mongo_uri = os.environ.get("TEST_MONGO_URI", "mongodb://localhost:27017/")

    config = {
        "API_TITLE": "dservercore API",
        "API_VERSION": "v1",
        "OPENAPI_VERSION": "3.0.2",
        "SECRET_KEY": "secret",
        "FLASK_ENV": "development",
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "RETRIEVE_MONGO_URI": mongo_uri,
        "RETRIEVE_MONGO_DB": tmp_mongo_db_name,
        "RETRIEVE_MONGO_COLLECTION": "datasets",
        "SEARCH_MONGO_URI": mongo_uri,
        "SEARCH_MONGO_DB": tmp_mongo_db_name,
        "SEARCH_MONGO_COLLECTION": "datasets",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "JWT_ALGORITHM": "RS256",
        "JWT_PUBLIC_KEY": JWT_PUBLIC_KEY,
        "JWT_TOKEN_LOCATION": "headers",
        "JWT_HEADER_NAME": "Authorization",
        "JWT_HEADER_TYPE": "Bearer",
        # Required by the dependency-graph extension, which is installed
        # in the test environment and auto-loaded via entry points.
        "MONGO_URI": mongo_uri,
        "MONGO_DB": tmp_mongo_db_name,
        "MONGO_COLLECTION": "dependencies",
    }

    app = create_app(config)
    app.app_context().push()
    sql_db.Model.metadata.create_all(sql_db.engine)

    register_users([
        dict(username="snow-white", is_admin=True),
        dict(username="grumpy"),
        dict(username="sleepy"),
    ])
    register_base_uri(BASE_URI)
    register_permissions(BASE_URI, {
        "users_with_search_permissions": ["grumpy", "sleepy"],
        "users_with_register_permissions": ["grumpy"],
    })

    @request.addfinalizer
    def teardown():
        current_app.retrieve.client.drop_database(tmp_mongo_db_name)
        current_app.search.client.drop_database(tmp_mongo_db_name)
        sql_db.session.remove()

    return app


@pytest.fixture
def client(tmp_app_with_users):
    return tmp_app_with_users.test_client()


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def upload_request_body(**overrides):
    body = {
        "uuid": UUID,
        "name": "my-dataset",
        "creator_username": "grumpy",
        "frozen_at": 1700000000.0,
        "hash_function": "md5sum_hexdigest",
        "items": [{
            "relpath": "data.txt",
            "size_in_bytes": 12,
            "hash": "9a0364b9e99bb480dd25e1f0284c8555",
            "utc_timestamp": 1700000000.0,
        }],
        "tags": ["science"],
        "annotations": {"project": "test"},
        "overlays": {},
    }
    body.update(overrides)
    return body
