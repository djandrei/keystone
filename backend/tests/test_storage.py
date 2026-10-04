"""S3ObjectStore over a mocked boto client (no S3 server)."""

from __future__ import annotations

import io

import pytest
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

    buckets: set = set()
    head_bucket_error = "404"

    def head_bucket(self, Bucket):
        if Bucket not in self.buckets:
            raise ClientError({"Error": {"Code": self.head_bucket_error}}, "HeadBucket")

    def create_bucket(self, Bucket):
        self.buckets = self.buckets | {Bucket}


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


def test_ensure_bucket_creates_a_missing_bucket_once():
    s = _store()
    assert s.ensure_bucket() is True
    assert s._client.buckets == {"bkt"}
    assert s.ensure_bucket() is False  # already there: no-op


def test_ensure_bucket_propagates_errors_other_than_missing():
    # wrong credentials must fail loudly, not be mistaken for "create it"
    s = _store()
    s._client.head_bucket_error = "403"
    with pytest.raises(ClientError):
        s.ensure_bucket()
    assert s._client.buckets == set()
