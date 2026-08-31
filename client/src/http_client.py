"""Minimal JSON HTTP client using the standard library, no vault-specific logic."""

from __future__ import annotations

import json
from urllib import request, parse, error


class ApiError(RuntimeError):
    """Raised when the server returns a non-2xx response."""

    def __init__(self, status_code: int, detail: str):
        super().__init__(f"request failed ({status_code}): {detail}")
        self.status_code = status_code
        self.detail = detail


def post_json(url: str, data: dict) -> dict:
    body = json.dumps(data).encode("utf-8")
    req = request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with request.urlopen(req) as resp:
            return json.load(resp)
    except error.HTTPError as e:
        error_body = json.load(e)
        raise ApiError(e.code, error_body.get("detail", str(error_body))) from e


def get_json(url: str, params: dict) -> dict:
    query_string = parse.urlencode(params)
    req = request.Request(f"{url}?{query_string}", method="GET")
    try:
        with request.urlopen(req) as resp:
            return json.load(resp)
    except error.HTTPError as e:
        error_body = json.load(e)
        raise ApiError(e.code, error_body.get("detail", str(error_body))) from e