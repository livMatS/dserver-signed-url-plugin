"""Marshmallow schemas for dserver-signed-url-plugin."""

from marshmallow import Schema, fields


class SignedURLsResponseSchema(Schema):
    """Schema for signed URLs response."""
    uri = fields.Str(required=True, metadata={"description": "Dataset URI"})
    expiry_seconds = fields.Int(required=True, metadata={"description": "URL expiry time in seconds"})
    expiry_timestamp = fields.Str(required=True, metadata={"description": "ISO format expiry timestamp"})
    admin_metadata_url = fields.Str(required=True, metadata={"description": "Signed URL for admin metadata"})
    manifest_url = fields.Str(required=True, metadata={"description": "Signed URL for manifest"})
    readme_url = fields.Str(required=True, metadata={"description": "Signed URL for README"})
    item_urls = fields.Dict(keys=fields.Str(), values=fields.Str(), metadata={"description": "Item identifier to signed URL mapping"})
    overlay_urls = fields.Dict(keys=fields.Str(), values=fields.Str(), metadata={"description": "Overlay name to signed URL mapping"})
    annotation_urls = fields.Dict(keys=fields.Str(), values=fields.Str(), metadata={"description": "Annotation name to signed URL mapping"})
    tags = fields.List(fields.Str(), metadata={"description": "Dataset tags"})


class SignedItemURLResponseSchema(Schema):
    """Schema for single item signed URL response."""
    uri = fields.Str(required=True, metadata={"description": "Dataset URI"})
    identifier = fields.Str(required=True, metadata={"description": "Item identifier"})
    expiry_seconds = fields.Int(required=True, metadata={"description": "URL expiry time in seconds"})
    expiry_timestamp = fields.Str(required=True, metadata={"description": "ISO format expiry timestamp"})
    url = fields.Str(required=True, metadata={"description": "Signed URL for the item"})


class UploadItemSchema(Schema):
    """Schema for an item to upload - includes full metadata for manifest generation."""
    relpath = fields.Str(required=True, metadata={"description": "Relative path of the item"})
    size_in_bytes = fields.Int(required=True, metadata={"description": "Size of the item in bytes"})
    hash = fields.Str(required=True, metadata={"description": "Hash of the item content"})
    utc_timestamp = fields.Float(required=True, metadata={"description": "UTC timestamp of the item"})


class UploadRequestSchema(Schema):
    """Schema for upload URL request.

    The server uses this metadata to create admin_metadata, manifest, structure,
    tags, and annotations directly in storage. Only README and items need
    separate uploads via signed URLs.
    """
    uuid = fields.Str(required=True, metadata={"description": "Dataset UUID"})
    name = fields.Str(required=True, metadata={"description": "Dataset name"})
    creator_username = fields.Str(required=True, metadata={"description": "Username of the dataset creator"})
    frozen_at = fields.Float(required=True, metadata={"description": "UTC timestamp when dataset was frozen"})
    items = fields.List(fields.Nested(UploadItemSchema), metadata={"description": "List of items with full metadata"})
    tags = fields.List(fields.Str(), load_default=[], metadata={"description": "List of tags"})
    annotations = fields.Dict(keys=fields.Str(), values=fields.Raw(), load_default={}, metadata={"description": "Annotations as key-value pairs"})


class UploadItemURLSchema(Schema):
    """Schema for an item upload URL."""
    url = fields.Str(required=True, metadata={"description": "Signed URL for uploading the item"})
    relpath = fields.Str(required=True, metadata={"description": "Relative path of the item"})


class UploadURLsSchema(Schema):
    """Schema for upload structure URLs.

    Only includes URLs for README and items - other metadata is written
    directly by the server.
    """
    readme = fields.Str(required=True, metadata={"description": "Signed URL for README"})
    items = fields.Dict(keys=fields.Str(), values=fields.Nested(UploadItemURLSchema), metadata={"description": "Item identifier to upload URL mapping"})


class UploadURLsResponseSchema(Schema):
    """Schema for upload URLs response."""
    uuid = fields.Str(required=True, metadata={"description": "Dataset UUID"})
    uri = fields.Str(required=True, metadata={"description": "Dataset URI"})
    base_uri = fields.Str(required=True, metadata={"description": "Base URI"})
    expiry_seconds = fields.Int(required=True, metadata={"description": "URL expiry time in seconds"})
    expiry_timestamp = fields.Str(required=True, metadata={"description": "ISO format expiry timestamp"})
    upload_urls = fields.Nested(UploadURLsSchema, metadata={"description": "Upload URLs"})


class UploadCompleteRequestSchema(Schema):
    """Schema for upload complete request."""
    uri = fields.Str(required=True, metadata={"description": "Dataset URI"})


class UploadCompleteResponseSchema(Schema):
    """Schema for upload complete response."""
    uri = fields.Str(required=True, metadata={"description": "Dataset URI"})
    status = fields.Str(required=True, metadata={"description": "Registration status"})
    name = fields.Str(required=True, metadata={"description": "Dataset name"})
    uuid = fields.Str(required=True, metadata={"description": "Dataset UUID"})
