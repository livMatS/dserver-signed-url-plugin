dserver-signed-url-plugin
=========================

A dserver extension plugin that enables dserver to act as a storage access
delegate by generating time-limited signed URLs for S3, Azure, and other
storage backends.

Overview
--------

This plugin solves a key access control challenge: traditionally, users need
direct credentials (AWS keys, Azure tokens) to access datasets stored in cloud
backends. This plugin allows dserver to act as an intermediary, generating
signed URLs on behalf of authenticated users based on their dserver permissions.

Architecture
------------

The plugin follows a backend-agnostic design::

    ┌─────────────────────────────────────────────────────────────────┐
    │                         Data Flow                               │
    ├─────────────────────────────────────────────────────────────────┤
    │                                                                 │
    │  User (no backend credentials)                                  │
    │         │                                                       │
    │         │ 1. Authenticate with dserver (JWT)                    │
    │         ▼                                                       │
    │  dserver-signed-url-plugin                                      │
    │         │                                                       │
    │         │ 2. Check permissions (may_search / may_register)      │
    │         │ 3. Load storage broker for backend                    │
    │         │ 4. Generate signed URLs                               │
    │         ▼                                                       │
    │  Storage Broker (dtool-s3 / dtool-azure)                        │
    │         │                                                       │
    │         │ 5. Create presigned URLs / SAS tokens                 │
    │         ▼                                                       │
    │  Cloud Backend (S3 / Azure / etc.)                              │
    │         │                                                       │
    │         │ 6. User downloads/uploads directly                    │
    │         ▼                                                       │
    │  User receives data                                             │
    │                                                                 │
    └─────────────────────────────────────────────────────────────────┘

Key benefits:

- **No credential sharing**: Users never see backend credentials
- **Centralized access control**: dserver's permission system controls all access
- **Time-limited access**: Signed URLs expire automatically
- **Backend agnostic**: Works with any storage broker that implements signing
- **Audit trail**: All access requests go through dserver

Installation
------------

.. code-block:: bash

    pip install dserver-signed-url-plugin

The plugin requires storage brokers with signing support:

.. code-block:: bash

    # For S3/MinIO backends
    pip install dtool-s3>=0.15.0

    # For Azure backends
    pip install dtool-azure>=0.8.0

Configuration
-------------

Environment variables:

``SIGNED_URL_READ_EXPIRY_SECONDS``
    Expiry time for read URLs in seconds. Default: 3600 (1 hour)

``SIGNED_URL_WRITE_EXPIRY_SECONDS``
    Expiry time for write/upload URLs in seconds. Default: 14400 (4 hours)

``DTOOL_CONFIG_PATH``
    Optional path to dtool configuration file

The plugin uses existing dtool storage broker configuration for backend
credentials. For S3, ensure these are set::

    DTOOL_S3_ENDPOINT_<bucket>=<endpoint_url>
    DTOOL_S3_ACCESS_KEY_ID_<bucket>=<access_key>
    DTOOL_S3_SECRET_ACCESS_KEY_<bucket>=<secret_key>

For Azure::

    DTOOL_AZURE_ACCOUNT_KEY_<account>=<account_key>

API Reference
-------------

All endpoints require JWT authentication via the ``Authorization: Bearer <token>``
header.

GET /signed-urls/dataset/<uri>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Get signed URLs for reading an entire dataset.

**URL Parameters:**

- ``uri``: URL-encoded dataset URI (e.g., ``s3%3A%2F%2Fbucket%2Fuuid``)

**Authorization:**

- User must have ``search`` permission on the dataset's base URI

**Response (200 OK):**

.. code-block:: json

    {
        "uri": "s3://bucket/uuid",
        "expiry_seconds": 3600,
        "expiry_timestamp": "2024-01-15T14:30:00.000000Z",
        "admin_metadata_url": "https://...",
        "manifest_url": "https://...",
        "readme_url": "https://...",
        "item_urls": {
            "abc123...": "https://...",
            "def456...": "https://..."
        },
        "overlay_urls": {
            "file_size": "https://..."
        },
        "annotation_urls": {
            "author": "https://..."
        },
        "tags": ["project-x", "2024"]
    }

**Error Responses:**

- ``403 Forbidden``: User lacks search permission on base URI
- ``404 Not Found``: Dataset not found in dserver
- ``501 Not Implemented``: Storage backend doesn't support signed URLs

GET /signed-urls/item/<uri>/<identifier>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Get a signed URL for a single dataset item. More efficient than fetching
URLs for the entire dataset when only one item is needed.

**URL Parameters:**

- ``uri``: URL-encoded dataset URI
- ``identifier``: Item identifier (SHA-1 hash of relpath)

**Authorization:**

- User must have ``search`` permission on the dataset's base URI

**Response (200 OK):**

.. code-block:: json

    {
        "uri": "s3://bucket/uuid",
        "identifier": "abc123...",
        "expiry_seconds": 3600,
        "expiry_timestamp": "2024-01-15T14:30:00.000000Z",
        "url": "https://..."
    }

POST /signed-urls/upload/<base_uri>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Get signed URLs for uploading a new dataset.

**URL Parameters:**

- ``base_uri``: URL-encoded base URI (e.g., ``s3%3A%2F%2Fbucket``)

**Request Body:**

.. code-block:: json

    {
        "uuid": "550e8400-e29b-41d4-a716-446655440000",
        "name": "my-dataset",
        "items": [
            {"relpath": "data/file1.txt"},
            {"relpath": "data/file2.csv"}
        ]
    }

**Authorization:**

- User must have ``register`` permission on the base URI

**Response (200 OK):**

.. code-block:: json

    {
        "uuid": "550e8400-e29b-41d4-a716-446655440000",
        "uri": "s3://bucket/550e8400-e29b-41d4-a716-446655440000",
        "base_uri": "s3://bucket",
        "expiry_seconds": 14400,
        "expiry_timestamp": "2024-01-15T18:30:00.000000Z",
        "upload_urls": {
            "admin_metadata": "https://...",
            "readme": "https://...",
            "manifest": "https://...",
            "structure": "https://...",
            "items": {
                "abc123...": {
                    "url": "https://...",
                    "relpath": "data/file1.txt"
                }
            }
        }
    }

**Error Responses:**

- ``403 Forbidden``: User lacks register permission on base URI
- ``409 Conflict``: Dataset with this UUID already exists

POST /signed-urls/upload-complete
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Signal that a dataset upload is complete. This triggers dataset validation
and registration in dserver.

**Request Body:**

.. code-block:: json

    {
        "uri": "s3://bucket/550e8400-e29b-41d4-a716-446655440000"
    }

**Authorization:**

- User must have ``register`` permission on the base URI

**Response (200 OK):**

.. code-block:: json

    {
        "uri": "s3://bucket/550e8400-e29b-41d4-a716-446655440000",
        "status": "registered",
        "name": "my-dataset",
        "uuid": "550e8400-e29b-41d4-a716-446655440000"
    }

**Error Responses:**

- ``400 Bad Request``: Dataset is incomplete or invalid
- ``403 Forbidden``: User lacks register permission

Usage Examples
--------------

Reading a Dataset (Python)
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    import requests

    # Authenticate
    token = "your-jwt-token"
    headers = {"Authorization": f"Bearer {token}"}

    # Get signed URLs for dataset
    uri = "s3://my-bucket/dataset-uuid"
    encoded_uri = requests.utils.quote(uri, safe="")

    response = requests.get(
        f"http://dserver:5000/signed-urls/dataset/{encoded_uri}",
        headers=headers
    )
    urls = response.json()

    # Download an item using the signed URL
    item_id = list(urls["item_urls"].keys())[0]
    item_response = requests.get(urls["item_urls"][item_id])
    with open("downloaded_file", "wb") as f:
        f.write(item_response.content)

Uploading a Dataset (Python)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    import requests
    import uuid
    import json
    import hashlib

    token = "your-jwt-token"
    headers = {"Authorization": f"Bearer {token}"}

    # Generate dataset UUID
    dataset_uuid = str(uuid.uuid4())

    # Prepare items
    items = [
        {"relpath": "data/file1.txt"},
        {"relpath": "data/file2.txt"}
    ]

    # Get upload URLs
    base_uri = "s3://my-bucket"
    encoded_base_uri = requests.utils.quote(base_uri, safe="")

    response = requests.post(
        f"http://dserver:5000/signed-urls/upload/{encoded_base_uri}",
        headers=headers,
        json={
            "uuid": dataset_uuid,
            "name": "my-new-dataset",
            "items": items
        }
    )
    upload_info = response.json()

    # Upload admin metadata
    admin_metadata = {
        "uuid": dataset_uuid,
        "name": "my-new-dataset",
        "type": "dataset",
        "creator_username": "user",
        "frozen_at": 1705312200.0
    }
    requests.put(
        upload_info["upload_urls"]["admin_metadata"],
        data=json.dumps(admin_metadata),
        headers={"Content-Type": "application/json"}
    )

    # Upload README
    readme = "---\ndescription: My dataset\n"
    requests.put(
        upload_info["upload_urls"]["readme"],
        data=readme,
        headers={"Content-Type": "text/plain"}
    )

    # Upload items
    for relpath, content in [("data/file1.txt", b"content1"), ...]:
        identifier = hashlib.sha1(relpath.encode()).hexdigest()
        item_url = upload_info["upload_urls"]["items"][identifier]["url"]
        requests.put(item_url, data=content)

    # Upload manifest
    manifest = {"items": {...}}  # Build manifest
    requests.put(
        upload_info["upload_urls"]["manifest"],
        data=json.dumps(manifest),
        headers={"Content-Type": "application/json"}
    )

    # Signal upload complete
    response = requests.post(
        "http://dserver:5000/signed-urls/upload-complete",
        headers=headers,
        json={"uri": upload_info["uri"]}
    )
    print(f"Dataset registered: {response.json()}")

Integration with dtool-dserver
------------------------------

For command-line access, use the ``dtool-dserver`` storage broker which
provides a standard dtool interface backed by this plugin::

    # Set authentication
    export DSERVER_TOKEN="your-jwt-token"

    # List datasets through dserver
    dtool ls dserver://localhost:5000/s3/my-bucket/

    # Copy a dataset to local storage
    dtool cp dserver://localhost:5000/s3/my-bucket/uuid /local/path/

    # Create a new dataset through dserver
    dtool create dserver://localhost:5000/s3/my-bucket/my-dataset

Pending Upload Management
-------------------------

When a client initiates a dataset upload, a proto-dataset is created in storage
and a record is stored in the database to track the pending upload. This allows
the server to:

1. Detect incomplete/abandoned uploads
2. Persist upload state across server restarts
3. Clean up stale uploads

Database Model
~~~~~~~~~~~~~~

The plugin adds a ``pending_upload`` table to the dserver database with the
following fields:

- ``uuid``: Dataset UUID (unique)
- ``uri``: Full dataset URI
- ``base_uri``: Base URI for the dataset
- ``name``: Dataset name
- ``creator_username``: Who initiated the upload
- ``created_at``: When the upload was initiated
- ``frozen_at``: Timestamp to use when freezing
- ``manifest_json``: JSON-serialized manifest data

After deploying this plugin, run database migrations to create the table::

    flask db migrate -m "Add pending_upload table"
    flask db upgrade

CLI Commands
~~~~~~~~~~~~

The plugin provides Flask CLI commands for managing pending uploads:

**List pending uploads**::

    # List all pending uploads
    flask pending_upload list

    # List uploads older than 24 hours
    flask pending_upload list --older-than 24

Output example::

    Found 2 pending upload(s):

      UUID: 550e8400-e29b-41d4-a716-446655440000
      Name: my-dataset
      URI: s3://bucket/550e8400-e29b-41d4-a716-446655440000
      Creator: admin
      Created: 2024-01-15T10:30:00 (26.5 hours ago)
      Items: 5

      UUID: 660e8400-e29b-41d4-a716-446655440001
      Name: another-dataset
      URI: s3://bucket/660e8400-e29b-41d4-a716-446655440001
      Creator: user1
      Created: 2024-01-15T12:00:00 (25.0 hours ago)
      Items: 3

**Clean up stale uploads**::

    # Preview what would be deleted (dry run)
    flask pending_upload cleanup --older-than 48 --dry-run

    # Actually delete uploads older than 48 hours
    flask pending_upload cleanup --older-than 48

    # Also attempt to delete proto-datasets from storage
    flask pending_upload cleanup --older-than 48 --delete-storage

**Delete a specific pending upload**::

    # Delete by UUID
    flask pending_upload delete 550e8400-e29b-41d4-a716-446655440000

    # Also attempt to delete from storage
    flask pending_upload delete 550e8400-e29b-41d4-a716-446655440000 --delete-storage

Docker Compose Usage
~~~~~~~~~~~~~~~~~~~~

When running dserver in Docker Compose::

    # List pending uploads
    docker compose exec dserver flask pending_upload list

    # Clean up uploads older than 24 hours
    docker compose exec dserver flask pending_upload cleanup --older-than 24

Automated Cleanup
~~~~~~~~~~~~~~~~~

For production deployments, consider setting up a cron job or scheduled task
to periodically clean up stale pending uploads::

    # Run daily at 2 AM to clean up uploads older than 48 hours
    0 2 * * * docker compose exec -T dserver flask pending_upload cleanup --older-than 48

Upload Workflow
~~~~~~~~~~~~~~~

The upload process works as follows:

1. **Upload initiation** (``POST /signed-urls/upload/<base_uri>``):

   - Creates a proto-dataset in storage (type: ``protodataset``)
   - Stores manifest and metadata in ``pending_upload`` table
   - Returns signed URLs for README and item uploads

2. **Data upload** (client-side):

   - Client uploads README and items using signed URLs
   - Client computes hashes during upload

3. **Upload completion** (``POST /signed-urls/upload-complete``):

   - Retrieves pending upload record from database
   - Freezes proto-dataset with stored manifest (type: ``dataset``)
   - Registers dataset in dserver
   - Deletes pending upload record

This architecture provides clear visibility into upload state:

- **Proto-datasets** (``type: protodataset``) indicate incomplete uploads
- **Datasets** (``type: dataset``) indicate completed, frozen datasets
- **Pending upload records** track uploads in progress

Security Considerations
-----------------------

1. **URL Expiry**: Signed URLs are time-limited. Choose appropriate expiry
   times based on your use case. Shorter times are more secure but may
   cause issues with large file uploads.

2. **Backend Credentials**: Backend credentials (AWS keys, Azure tokens)
   are only held by dserver, never exposed to users.

3. **Permission Inheritance**: Access is controlled by dserver's permission
   system. Users can only generate signed URLs for datasets/base URIs they
   have permission to access.

4. **HTTPS**: In production, always use HTTPS for dserver to protect JWT
   tokens in transit.

5. **Token Security**: JWT tokens grant access to generate signed URLs.
   Treat them as sensitive credentials.

Storage Broker Requirements
---------------------------

For a storage broker to work with this plugin, it must implement:

.. code-block:: python

    class MyStorageBroker:
        def generate_signed_read_url(self, key, expiry_seconds=3600):
            """Generate a time-limited URL for reading an object."""
            ...

        def generate_signed_write_url(self, key, expiry_seconds=3600):
            """Generate a time-limited URL for writing an object."""
            ...

        def generate_dataset_signed_urls(self, expiry_seconds=3600):
            """Generate all signed URLs for a dataset."""
            ...

        def supports_signing(self):
            """Return True if this broker supports signing."""
            return True

Currently supported brokers:

- ``dtool-s3`` >= 0.15.0 (S3, MinIO, and S3-compatible)
- ``dtool-azure`` >= 0.8.0 (Azure Blob Storage)

License
-------

MIT License
