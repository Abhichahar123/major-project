"""Unit tests for the upstream HTTP client (all traffic is mocked)."""

from __future__ import annotations

import httpx
import pytest

from app.ingestion.http import (
    DisallowedHostError,
    ResponseTooLargeError,
    SourceError,
    SourceHttpClient,
    SourceNotFoundError,
)

HOST = "data.example.org"
URL = f"https://{HOST}/feed.json"


def make_client(handler, **kwargs):  # type: ignore[no-untyped-def]
    sleeps: list[float] = []
    client = SourceHttpClient(
        allowed_hosts={HOST},
        transport=httpx.MockTransport(handler),
        sleep=sleeps.append,
        backoff_base_seconds=0.5,
        **kwargs,
    )
    return client, sleeps


def test_retries_transient_errors_then_succeeds() -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) < 3:
            return httpx.Response(503)
        return httpx.Response(200, json={"ok": True})

    client, sleeps = make_client(handler)
    assert client.get_json(URL) == {"ok": True}
    assert len(calls) == 3
    assert len(sleeps) == 2 and sleeps[1] >= sleeps[0] * 1.0  # exponential backoff


def test_retry_after_is_honoured_and_capped() -> None:
    responses = iter(
        [
            httpx.Response(429, headers={"Retry-After": "7"}),
            httpx.Response(429, headers={"Retry-After": "9999"}),
            httpx.Response(200, json=[]),
        ]
    )
    client, sleeps = make_client(lambda request: next(responses))
    client.get_json(URL)
    assert sleeps == [7.0, 60.0]


def test_timeouts_are_retried() -> None:
    attempts = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        if len(attempts) == 1:
            raise httpx.ReadTimeout("slow", request=request)
        return httpx.Response(200, json={})

    client, _ = make_client(handler)
    assert client.get_json(URL) == {}


def test_gives_up_after_max_retries() -> None:
    client, sleeps = make_client(lambda request: httpx.Response(502), max_retries=2)
    with pytest.raises(SourceError, match="giving up after 3 attempts"):
        client.get_json(URL)
    assert len(sleeps) == 2


def test_404_is_not_retried() -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(404)

    client, _ = make_client(handler)
    with pytest.raises(SourceNotFoundError):
        client.get_json(URL)
    assert len(calls) == 1


def test_other_4xx_fail_fast() -> None:
    client, sleeps = make_client(lambda request: httpx.Response(403))
    with pytest.raises(SourceError, match="403"):
        client.get_json(URL)
    assert sleeps == []


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/x",
        "http://data.example.org/insecure",
        "https://169.254.169.254/latest",
    ],
)
def test_only_allowlisted_https_hosts(url: str) -> None:
    client, _ = make_client(lambda request: httpx.Response(200, json={}))
    with pytest.raises(DisallowedHostError):
        client.get_json(url)


def test_redirects_are_not_followed() -> None:
    client, _ = make_client(
        lambda request: httpx.Response(302, headers={"Location": "https://evil.example/"})
    )
    with pytest.raises(SourceError, match="302"):
        client.get_json(URL)


def test_response_size_cap() -> None:
    client, _ = make_client(
        lambda request: httpx.Response(200, content=b"x" * 2048), max_response_bytes=1024
    )
    with pytest.raises(ResponseTooLargeError):
        client.get_bytes(URL)


def test_invalid_json_is_a_source_error() -> None:
    client, _ = make_client(lambda request: httpx.Response(200, content=b"{not json"))
    with pytest.raises(SourceError, match="invalid JSON"):
        client.get_json(URL)
