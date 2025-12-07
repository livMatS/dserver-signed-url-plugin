"""dserver plugin for generating signed URLs for dataset access."""

try:
    from importlib.metadata import version, PackageNotFoundError
except ModuleNotFoundError:
    from importlib_metadata import version, PackageNotFoundError

try:
    __version__ = version(__name__)
except PackageNotFoundError:
    # package is not installed
    pass

import json
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

import dtoolcore
import dtoolcore.utils

from flask import abort, current_app, jsonify
from flask_smorest import Blueprint

from dservercore import ExtensionABC
from dservercore.utils import (
    register_dataset,
    generate_dataset_info,
    dataset_uri_exists,
)
from dservercore.utils_auth import (
    jwt_required,
    get_jwt_identity,
    may_search,
    may_register,
)

from .config import Config, CONFIG_SECRETS_TO_OBFUSCATE
from .schemas import (
    SignedURLsResponseSchema,
    SignedItemURLResponseSchema,
    UploadRequestSchema,
    UploadURLsResponseSchema,
    UploadCompleteRequestSchema,
    UploadCompleteResponseSchema,
)


logger = logging.getLogger(__name__)


# Create the Flask-smorest blueprint
signed_url_bp = Blueprint(
    "signed-urls",
    __name__,
    url_prefix="/signed-urls",
    description="Endpoints for generating signed URLs for dataset access"
)


def _extract_base_uri(uri):
    """Extract base URI from dataset URI."""
    return uri.rsplit("/", 1)[0]


def _rewrite_url(url):
    """Rewrite URL if host rewriting is configured.

    This is used when dserver runs in a container and the internal
    hostname (e.g., 'minio') needs to be replaced with an externally
    accessible hostname (e.g., 'localhost').

    :param url: Original URL
    :returns: Rewritten URL (or original if no rewrite configured)
    """
    rewrite_config = Config.SIGNED_URL_HOST_REWRITE
    if not rewrite_config:
        return url

    # Parse the rewrite config - format is "internal:external"
    # where both can be full URLs like "http://minio:9000" or just "minio:9000"
    parts = rewrite_config.split(':', 1)
    if len(parts) != 2:
        logger.warning(f"Invalid SIGNED_URL_HOST_REWRITE format: {rewrite_config}")
        return url

    # Handle both "http://minio:9000" -> "http://localhost:9000" format
    # and simpler cases
    internal = parts[0]
    external = parts[1]

    # For URL-style config like "http://minio:9000:http://localhost:9000",
    # we need to be smarter about parsing
    if '://' in rewrite_config:
        # Split on "://" boundaries - find the second protocol marker
        idx = rewrite_config.find('://', rewrite_config.find('://') + 3)
        if idx > 0:
            # There's a second protocol - split there minus one for the colon separator
            # Format: http://minio:9000:http://localhost:9000
            # Find where "http" starts after the first URL
            for i, char in enumerate(rewrite_config):
                if i > 0 and rewrite_config[i-1] == ':' and rewrite_config[i:i+4] in ('http', 'HTTP'):
                    internal = rewrite_config[:i-1]
                    external = rewrite_config[i:]
                    break

    return url.replace(internal, external, 1)


def _rewrite_urls_dict(urls_dict):
    """Apply URL rewriting to all URLs in a dictionary.

    :param urls_dict: Dictionary potentially containing URL values
    :returns: Dictionary with rewritten URLs
    """
    result = {}
    for key, value in urls_dict.items():
        if isinstance(value, str) and ('://' in value):
            result[key] = _rewrite_url(value)
        elif isinstance(value, dict):
            result[key] = _rewrite_urls_dict(value)
        elif isinstance(value, list):
            result[key] = [
                _rewrite_url(v) if isinstance(v, str) and '://' in v else v
                for v in value
            ]
        else:
            result[key] = value
    return result


def _get_storage_broker(uri):
    """Get storage broker instance for a dataset URI.

    :param uri: Dataset URI
    :returns: Storage broker instance
    :raises: ValueError if broker doesn't support signing
    """
    try:
        dataset = dtoolcore.DataSet.from_uri(uri)
        storage_broker = dataset._storage_broker
    except Exception as e:
        logger.error(f"Failed to get storage broker for {uri}: {e}")
        raise ValueError(f"Cannot access dataset at {uri}: {e}")

    # Check if broker supports signing
    if not hasattr(storage_broker, 'generate_dataset_signed_urls'):
        raise ValueError(
            f"Storage broker {type(storage_broker).__name__} does not support "
            "signed URL generation"
        )

    return storage_broker


def _get_storage_broker_for_upload(base_uri, uuid):
    """Get storage broker instance for uploading a new dataset.

    This creates a broker for a dataset that doesn't exist yet.

    :param base_uri: Base URI (e.g., s3://bucket)
    :param uuid: Dataset UUID
    :returns: Storage broker instance
    """
    # Parse the base URI to get the scheme
    parsed = dtoolcore.utils.generous_parse_uri(base_uri)
    scheme = parsed.scheme

    # Get the storage broker class for this scheme
    storage_broker_lookup = dtoolcore._generate_storage_broker_lookup()
    if scheme not in storage_broker_lookup:
        raise ValueError(f"Unknown storage backend: {scheme}")

    StorageBrokerClass = storage_broker_lookup[scheme]

    # Generate the full URI
    uri = f"{base_uri}/{uuid}"

    # Create broker instance
    storage_broker = StorageBrokerClass(uri, config_path=Config.DTOOL_CONFIG_PATH)

    # Check if broker supports signing
    if not hasattr(storage_broker, 'generate_signed_write_url'):
        raise ValueError(
            f"Storage broker {StorageBrokerClass.__name__} does not support "
            "signed URL generation for writes"
        )

    return storage_broker


@signed_url_bp.route("/dataset/<path:uri>", methods=["GET"])
@signed_url_bp.response(200, SignedURLsResponseSchema)
@jwt_required()
def get_dataset_signed_urls(uri):
    """Get signed URLs for reading an entire dataset.

    Returns a set of time-limited signed URLs that can be used to download
    all components of a dataset (admin metadata, manifest, README, items,
    overlays, and annotations) without requiring direct storage backend
    credentials.
    """
    username = get_jwt_identity()
    uri = unquote(uri)
    base_uri = _extract_base_uri(uri)

    # Authorization check - user must have search permissions on base URI
    if not may_search(username, base_uri):
        logger.warning(
            f"User {username} denied access to signed URLs for {uri}: "
            "no search permission on base URI"
        )
        abort(403, description="No read access to this base URI")

    # Check dataset exists in dserver
    if not dataset_uri_exists(uri):
        logger.warning(f"Dataset not found in dserver: {uri}")
        abort(404, description="Dataset not found")

    # Get storage broker
    try:
        storage_broker = _get_storage_broker(uri)
    except ValueError as e:
        logger.error(f"Failed to get storage broker: {e}")
        abort(501, description=str(e))

    # Generate signed URLs
    expiry_seconds = Config.SIGNED_URL_READ_EXPIRY_SECONDS
    try:
        urls = storage_broker.generate_dataset_signed_urls(expiry_seconds)
    except Exception as e:
        logger.error(f"Failed to generate signed URLs for {uri}: {e}")
        abort(500, description=f"Failed to generate signed URLs: {e}")

    # Rewrite URLs if host rewriting is configured
    urls = _rewrite_urls_dict(urls)

    expiry_timestamp = (
        datetime.utcnow() + timedelta(seconds=expiry_seconds)
    ).isoformat() + "Z"

    return {
        'uri': uri,
        'expiry_seconds': expiry_seconds,
        'expiry_timestamp': expiry_timestamp,
        **urls
    }


@signed_url_bp.route("/item/<path:uri>/<identifier>", methods=["GET"])
@signed_url_bp.response(200, SignedItemURLResponseSchema)
@jwt_required()
def get_item_signed_url(uri, identifier):
    """Get signed URL for a single dataset item.

    Returns a time-limited signed URL for downloading a specific item
    from a dataset. This is more efficient than getting URLs for the
    entire dataset when only one item is needed.
    """
    username = get_jwt_identity()
    uri = unquote(uri)
    base_uri = _extract_base_uri(uri)

    # Authorization check
    if not may_search(username, base_uri):
        logger.warning(
            f"User {username} denied access to signed URL for item {identifier} "
            f"in {uri}: no search permission on base URI"
        )
        abort(403, description="No read access to this base URI")

    # Check dataset exists
    if not dataset_uri_exists(uri):
        abort(404, description="Dataset not found")

    # Get storage broker
    try:
        storage_broker = _get_storage_broker(uri)
    except ValueError as e:
        abort(501, description=str(e))

    # Get manifest to verify item exists
    try:
        manifest = storage_broker.get_manifest()
    except Exception as e:
        logger.error(f"Failed to get manifest for {uri}: {e}")
        abort(500, description=f"Failed to get manifest: {e}")

    if identifier not in manifest.get('items', {}):
        abort(404, description=f"Item {identifier} not found in dataset")

    # Generate signed URL for the item
    expiry_seconds = Config.SIGNED_URL_READ_EXPIRY_SECONDS
    try:
        item_key = storage_broker.data_key_prefix + identifier
        url = storage_broker.generate_signed_read_url(item_key, expiry_seconds)
    except Exception as e:
        logger.error(f"Failed to generate signed URL for item {identifier}: {e}")
        abort(500, description=f"Failed to generate signed URL: {e}")

    # Rewrite URL if host rewriting is configured
    url = _rewrite_url(url)

    expiry_timestamp = (
        datetime.utcnow() + timedelta(seconds=expiry_seconds)
    ).isoformat() + "Z"

    return {
        'uri': uri,
        'identifier': identifier,
        'expiry_seconds': expiry_seconds,
        'expiry_timestamp': expiry_timestamp,
        'url': url
    }


@signed_url_bp.route("/upload/<path:base_uri>", methods=["POST"])
@signed_url_bp.arguments(UploadRequestSchema)
@signed_url_bp.response(200, UploadURLsResponseSchema)
@jwt_required()
def get_upload_signed_urls(request_data, base_uri):
    """Get signed URLs for uploading a new dataset.

    The server writes admin_metadata, manifest, structure, tags, and annotations
    directly to storage based on the provided metadata. Only README and items
    need to be uploaded by the client using the returned signed URLs.

    After uploading README and items, the client should call the upload-complete
    endpoint to trigger dataset indexing.
    """
    username = get_jwt_identity()
    base_uri = unquote(base_uri)

    # Authorization check - user must have register permissions
    if not may_register(username, base_uri):
        logger.warning(
            f"User {username} denied upload to {base_uri}: "
            "no register permission"
        )
        abort(403, description="No write access to this base URI")

    uuid = request_data['uuid']
    name = request_data['name']
    creator_username = request_data['creator_username']
    frozen_at = request_data['frozen_at']
    items = request_data.get('items', [])
    tags = request_data.get('tags', [])
    annotations = request_data.get('annotations', {})

    # Generate dataset URI
    dataset_uri = f"{base_uri}/{uuid}"

    # Check if dataset already exists
    if dataset_uri_exists(dataset_uri):
        abort(409, description=f"Dataset {uuid} already exists at {base_uri}")

    # Get storage broker for upload
    try:
        storage_broker = _get_storage_broker_for_upload(base_uri, uuid)
    except ValueError as e:
        abort(501, description=str(e))

    expiry_seconds = Config.SIGNED_URL_WRITE_EXPIRY_SECONDS
    prefix = uuid + "/"

    try:
        # Build admin metadata
        admin_metadata = {
            "uuid": uuid,
            "dtoolcore_version": dtoolcore.__version__,
            "name": name,
            "type": "dataset",
            "creator_username": creator_username,
            "frozen_at": frozen_at,
        }

        # Build manifest with items
        manifest_items = {}
        for item in items:
            relpath = item['relpath']
            identifier = dtoolcore.utils.generate_identifier(relpath)
            manifest_items[identifier] = {
                "relpath": relpath,
                "size_in_bytes": item['size_in_bytes'],
                "hash": item['hash'],
                "utc_timestamp": item['utc_timestamp'],
            }

        manifest = {
            "dtoolcore_version": dtoolcore.__version__,
            "hash_function": "md5sum_hexdigest",
            "items": manifest_items,
        }

        # Structure parameters (server-defined, appropriate for the backend)
        structure_parameters = {
            "data_key_infix": "data",
            "fragment_key_infix": "fragments",
            "overlays_key_infix": "overlays",
            "annotations_key_infix": "annotations",
            "tags_key_infix": "tags",
            "structure_key_suffix": "structure.json",
            "dtool_readme_key_suffix": "README.txt",
            "dataset_readme_key_suffix": "README.yml",
            "manifest_key_suffix": "manifest.json",
            "admin_metadata_key_suffix": "dtool",
            "http_manifest_key": "http_manifest.json",
            "storage_broker_version": dtoolcore.__version__,
        }

        # Write admin metadata directly to storage
        logger.debug(f"Writing admin metadata for {dataset_uri}")
        storage_broker.put_text(
            prefix + "dtool",
            json.dumps(admin_metadata)
        )

        # Write manifest directly to storage
        logger.debug(f"Writing manifest for {dataset_uri}")
        storage_broker.put_text(
            prefix + "manifest.json",
            json.dumps(manifest)
        )

        # Write structure.json directly to storage
        logger.debug(f"Writing structure.json for {dataset_uri}")
        storage_broker.put_text(
            prefix + "structure.json",
            json.dumps(structure_parameters, indent=2, sort_keys=True)
        )

        # Write tags directly to storage (empty files)
        for tag in tags:
            logger.debug(f"Writing tag '{tag}' for {dataset_uri}")
            storage_broker.put_text(prefix + "tags/" + tag, "")

        # Write annotations directly to storage (JSON files)
        for annotation_name, annotation_value in annotations.items():
            logger.debug(f"Writing annotation '{annotation_name}' for {dataset_uri}")
            storage_broker.put_text(
                prefix + "annotations/" + annotation_name + ".json",
                json.dumps(annotation_value, indent=2)
            )

        # Generate signed URLs only for README and items
        upload_urls = {
            'readme': storage_broker.generate_signed_write_url(
                prefix + "README.yml", expiry_seconds),
            'items': {}
        }

        # Generate URLs for each item
        for item in items:
            relpath = item['relpath']
            identifier = dtoolcore.utils.generate_identifier(relpath)
            item_key = prefix + "data/" + identifier
            upload_urls['items'][identifier] = {
                'url': storage_broker.generate_signed_write_url(
                    item_key, expiry_seconds),
                'relpath': relpath
            }

    except Exception as e:
        logger.error(f"Failed to process upload request for {dataset_uri}: {e}")
        abort(500, description=f"Failed to process upload request: {e}")

    # Rewrite URLs if host rewriting is configured
    upload_urls = _rewrite_urls_dict(upload_urls)

    expiry_timestamp = (
        datetime.now(timezone.utc) + timedelta(seconds=expiry_seconds)
    ).isoformat()

    return {
        'uuid': uuid,
        'uri': dataset_uri,
        'base_uri': base_uri,
        'expiry_seconds': expiry_seconds,
        'expiry_timestamp': expiry_timestamp,
        'upload_urls': upload_urls
    }


@signed_url_bp.route("/upload-complete", methods=["POST"])
@signed_url_bp.arguments(UploadCompleteRequestSchema)
@signed_url_bp.response(200, UploadCompleteResponseSchema)
@jwt_required()
def signal_upload_complete(request_data):
    """Signal that a dataset upload is complete.

    After uploading all dataset components using the signed URLs from
    the upload endpoint, call this endpoint to trigger dataset indexing
    and registration in dserver.
    """
    username = get_jwt_identity()
    uri = request_data['uri']
    base_uri = _extract_base_uri(uri)

    # Authorization check
    if not may_register(username, base_uri):
        logger.warning(
            f"User {username} denied upload-complete for {uri}: "
            "no register permission"
        )
        abort(403, description="No write access to this base URI")

    # Load dataset using dtoolcore to validate it
    try:
        dataset = dtoolcore.DataSet.from_uri(uri)
    except dtoolcore.DtoolCoreTypeError as e:
        logger.warning(f"Upload complete but dataset invalid: {uri} - {e}")
        abort(400, description=f"Invalid or incomplete dataset: {e}")
    except Exception as e:
        logger.error(f"Failed to load dataset {uri}: {e}")
        abort(400, description=f"Failed to load dataset: {e}")

    # Generate dataset info for registration
    try:
        dataset_info = generate_dataset_info(dataset, base_uri)
    except Exception as e:
        logger.error(f"Failed to generate dataset info for {uri}: {e}")
        abort(500, description=f"Failed to generate dataset info: {e}")

    # Register in dserver
    try:
        register_dataset(dataset_info)
    except Exception as e:
        logger.error(f"Failed to register dataset {uri}: {e}")
        abort(500, description=f"Failed to register dataset: {e}")

    logger.info(f"Successfully registered dataset from upload: {uri}")

    return {
        'uri': uri,
        'status': 'registered',
        'name': dataset.name,
        'uuid': dataset.uuid
    }


class SignedURLExtension(ExtensionABC):
    """dserver extension for generating signed URLs for dataset access.

    This extension allows dserver to act as a storage access delegate,
    generating time-limited signed URLs for S3, Azure, and other storage
    backends. Users can access datasets through dserver without requiring
    direct backend credentials.
    """

    def init_app(self, app):
        """Initialize the extension with the Flask app."""
        # Register configuration
        app.config.setdefault(
            'SIGNED_URL_READ_EXPIRY_SECONDS',
            Config.SIGNED_URL_READ_EXPIRY_SECONDS
        )
        app.config.setdefault(
            'SIGNED_URL_WRITE_EXPIRY_SECONDS',
            Config.SIGNED_URL_WRITE_EXPIRY_SECONDS
        )

        logger.info(
            f"SignedURLExtension initialized with read_expiry="
            f"{Config.SIGNED_URL_READ_EXPIRY_SECONDS}s, write_expiry="
            f"{Config.SIGNED_URL_WRITE_EXPIRY_SECONDS}s"
        )

    def register_dataset(self, dataset_info):
        """Called when a dataset is registered - no action needed."""
        pass

    def get_config(self):
        """Return initial Config object."""
        return Config

    def get_config_secrets_to_obfuscate(self):
        """Return config secrets never to be exposed clear text."""
        return CONFIG_SECRETS_TO_OBFUSCATE

    def get_blueprint(self):
        """Return the Flask blueprint for this extension."""
        return signed_url_bp
