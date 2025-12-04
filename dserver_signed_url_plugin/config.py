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
