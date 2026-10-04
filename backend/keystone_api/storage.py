"""Content-addressed object storage over S3 (boto3; VersityGW in compose).

Keys are `binaries/{sha256}` so identical bytes dedupe to one object regardless
of how many teams upload them. The store is injectable (app.config['OBJECT_STORE'])
so tests use an in-memory fake and never need a live S3 server."""

from __future__ import annotations

from functools import lru_cache
from typing import Protocol, runtime_checkable

from .config import Settings, get_settings


@runtime_checkable
class ObjectStore(Protocol):
    def put(self, key: str, data: bytes) -> None: ...
    def exists(self, key: str) -> bool: ...
    def get(self, key: str) -> bytes: ...
    def delete(self, key: str) -> None: ...


class S3ObjectStore:
    def __init__(self, settings: Settings) -> None:
        import boto3

        self._bucket = settings.s3_bucket
        self._client = boto3.client(
            "s3",
            endpoint_url=settings.s3_endpoint,
            aws_access_key_id=settings.s3_access_key,
            aws_secret_access_key=settings.s3_secret_key,
            region_name="us-east-1",
        )

    def put(self, key: str, data: bytes) -> None:
        self._client.put_object(Bucket=self._bucket, Key=key, Body=data)

    def exists(self, key: str) -> bool:
        from botocore.exceptions import ClientError

        try:
            self._client.head_object(Bucket=self._bucket, Key=key)
            return True
        except ClientError:
            return False

    def get(self, key: str) -> bytes:
        return self._client.get_object(Bucket=self._bucket, Key=key)["Body"].read()

    def delete(self, key: str) -> None:
        # S3 delete_object is idempotent — deleting a missing key is not an error.
        self._client.delete_object(Bucket=self._bucket, Key=key)

    def ensure_bucket(self) -> bool:
        """Create the bucket if it is missing; True if it was created.

        Run once at stack start (`cli init-storage`). Any error other than
        "no such bucket" -- wrong credentials, unreachable server -- propagates."""
        from botocore.exceptions import ClientError

        try:
            self._client.head_bucket(Bucket=self._bucket)
            return False
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("404", "NoSuchBucket"):
                raise
        self._client.create_bucket(Bucket=self._bucket)
        return True


@lru_cache
def get_object_store() -> ObjectStore:
    return S3ObjectStore(get_settings())
