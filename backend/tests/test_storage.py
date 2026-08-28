"""S3ObjectStore over a mocked boto client (no MinIO)."""

from __future__ import annotations

import io

from botocore.exceptions import ClientError

from keystone_api.storage import S3ObjectStore, get_object_store


class FakeClient:
    def __init__(self):
        self.store: dict[tuple, bytes] = {}

    def put_object(self, Bucket, Key, Body):
        self.store[(Bucket, Key)] = Body

    def head_object(self, Bucket, Key):
        if (Bucket, Key) not in self.store:
            raise ClientError({"Error": {"Code": "404"}}, "HeadObject")

    def get_object(self, Bucket, Key):
        return {"Body": io.BytesIO(self.store[(Bucket, Key)])}

    def delete_object(self, Bucket, Key):
        self.store.pop((Bucket, Key), None)


def _store():
    s = S3ObjectStore.__new__(S3ObjectStore)
    s._bucket = "bkt"
    s._client = FakeClient()
    return s


def test_put_exists_get_delete_roundtrip():
    s = _store()
    assert s.exists("binaries/k") is False  # ClientError -> False
    s.put("binaries/k", b"data")
    assert s.exists("binaries/k") is True
    assert s.get("binaries/k") == b"data"
    s.delete("binaries/k")
    assert s.exists("binaries/k") is False


def test_get_object_store_builds_an_s3_store():
    # construction only (boto3.client doesn't connect)
    assert isinstance(get_object_store(), S3ObjectStore)
