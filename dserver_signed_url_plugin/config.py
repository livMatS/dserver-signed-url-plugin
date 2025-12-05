"""Configuration for dserver-signed-url-plugin."""

import os


AFFIRMATIVE_EXPRESSIONS = ['true', '1', 'y', 'yes', 'on']


CONFIG_SECRETS_TO_OBFUSCATE = []


class Config:
    """Configuration for signed URL generation."""

    # Default expiry time for read URLs (1 hour)
    SIGNED_URL_READ_EXPIRY_SECONDS = int(
        os.environ.get('SIGNED_URL_READ_EXPIRY_SECONDS', '3600')
    )

    # Default expiry time for write URLs (4 hours)
    SIGNED_URL_WRITE_EXPIRY_SECONDS = int(
        os.environ.get('SIGNED_URL_WRITE_EXPIRY_SECONDS', '14400')
    )

    # dtool config path (for storage broker initialization)
    DTOOL_CONFIG_PATH = os.environ.get('DTOOL_CONFIG_PATH', None)

    # URL rewriting for signed URLs
    # When dserver runs in a container, the internal endpoint (e.g., http://minio:9000)
    # may not be accessible from outside. This allows rewriting URLs for external access.
    # Format: "internal_base_url:external_base_url"
    # Example: "http://minio:9000:http://localhost:9000"
    SIGNED_URL_HOST_REWRITE = os.environ.get('SIGNED_URL_HOST_REWRITE', None)

    # Default base URI for short dserver URI format
    # Example: "s3://dtool-bucket"
    # When set, allows dtool-dserver to use short URIs like dserver://server/uuid
    DSERVER_DEFAULT_BASE_URI = os.environ.get('DSERVER_DEFAULT_BASE_URI', None)
