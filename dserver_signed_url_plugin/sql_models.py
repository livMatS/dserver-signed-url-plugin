"""Database models for pending uploads."""

import json
from datetime import datetime, timezone

from dservercore import sql_db as db


class PendingUpload(db.Model):
    """Track pending dataset uploads that have not yet been finalized.

    When a client initiates an upload via the signed URL plugin, a proto-dataset
    is created in storage and a PendingUpload record is created here. This record
    stores the manifest and other metadata needed to freeze the dataset when the
    upload is completed.

    This allows:
    1. Detection of incomplete/abandoned uploads
    2. Persistence across server restarts
    3. Cleanup of stale uploads
    """
    __tablename__ = "pending_upload"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), index=True, unique=True, nullable=False)
    uri = db.Column(db.String(255), index=True, nullable=False)
    base_uri = db.Column(db.String(255), index=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    creator_username = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(), nullable=False, default=lambda: datetime.now(timezone.utc))
    frozen_at = db.Column(db.Float, nullable=False)  # Timestamp to use when freezing
    manifest_json = db.Column(db.Text, nullable=False)  # JSON-serialized manifest

    def __repr__(self):
        return f"<PendingUpload {self.uuid} ({self.name})>"

    @property
    def manifest(self):
        """Deserialize the manifest from JSON."""
        return json.loads(self.manifest_json)

    @manifest.setter
    def manifest(self, value):
        """Serialize the manifest to JSON."""
        self.manifest_json = json.dumps(value)

    def as_dict(self):
        """Return pending upload as dictionary."""
        return {
            "uuid": self.uuid,
            "uri": self.uri,
            "base_uri": self.base_uri,
            "name": self.name,
            "creator_username": self.creator_username,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "frozen_at": self.frozen_at,
            "manifest": self.manifest,
        }
