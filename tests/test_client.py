# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import annotations

from copy import deepcopy

import pytest

from src.asset import Asset as SoarAsset
from src.infoblox_client import InfobloxApiError, InfobloxClient


class FakeResponse:
    def __init__(self, status_code: int, data=None, *, headers=None, text=""):
        self.status_code = status_code
        self._data = data
        self.headers = headers or {"Content-Type": "application/json"}
        self.text = text

    def json(self):
        if isinstance(self._data, Exception):
            raise self._data
        return self._data


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.headers = {}
        self.cookies = {"ibapauth": "session-cookie"}
        self.closed = False

    def _call(self, method, url, **kwargs):
        self.calls.append((method, url, deepcopy(kwargs)))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def request(self, method, url, **kwargs):
        return self._call(method.lower(), url, **kwargs)

    def get(self, url, **kwargs):
        return self._call("get", url, **kwargs)

    def post(self, url, **kwargs):
        return self._call("post", url, **kwargs)

    def put(self, url, **kwargs):
        return self._call("put", url, **kwargs)

    def delete(self, url, **kwargs):
        return self._call("delete", url, **kwargs)

    def close(self):
        self.closed = True


class Asset:
    url = "https://grid.example/"
    username = "api-user"
    password = "pwd"  # pragma: allowlist secret
    verify_server_cert = False


def test_request_preserves_url_auth_tls_and_timeout_contract():
    session = FakeSession([FakeResponse(200, [{"answer": 42, "enabled": False, "extra": None}])])
    client = InfobloxClient(Asset(), session=session)

    response = client.wapi_request("/network", method="get", params={"network_view": "default"})

    assert response.data == [{"answer": 42, "enabled": False, "extra": None}]
    method, url, kwargs = session.calls[0]
    assert (method, url) == ("get", "https://grid.example/wapi/v2.3.1/network")
    assert kwargs == {
        "auth": ("api-user", "pwd"),
        "params": {"network_view": "default"},
        "data": None,
        "verify": False,
    }


def test_verify_server_cert_is_optional_and_defaults_to_verification():
    field = SoarAsset.model_fields["verify_server_cert"]
    assert not field.is_required()
    assert field.default is True

    config = SoarAsset.model_validate({"url": "https://grid.example", "username": "u", "password": "p"})
    assert config.verify_server_cert is True
    client = InfobloxClient(config)
    assert client.verify_ssl is True
    client.close()


def test_paged_request_combines_results_and_keeps_page_query_shape():
    session = FakeSession(
        [
            FakeResponse(200, {"result": [{"id": 1}], "next_page_id": "next"}),
            FakeResponse(200, {"result": [{"id": 2}], "next_page_id": None}),
        ]
    )
    client = InfobloxClient(Asset(), session=session)
    original = {"network_view": "default"}

    assert client.paged_request("/network", params=original) == [
        {"id": 1},
        {"id": 2},
    ]
    assert original == {"network_view": "default"}
    first = session.calls[0][2]["params"]
    second = session.calls[1][2]["params"]
    assert first == {
        "network_view": "default",
        "_paging": 1,
        "_return_as_object": 1,
        "_max_results": 1000,
    }
    assert second == {"_page_id": "next", "_paging": 1, "_return_as_object": 1}


def test_pagination_stops_on_repeated_page_id():
    session = FakeSession(
        [
            FakeResponse(200, {"result": [], "next_page_id": "same"}),
            FakeResponse(200, {"result": [], "next_page_id": "same"}),
        ]
    )
    client = InfobloxClient(Asset(), session=session)

    with pytest.raises(InfobloxApiError, match="server repeated next_page_id"):
        client.paged_request("/network")


def test_http_error_uses_server_detail_and_maps_known_statuses():
    client = InfobloxClient(
        Asset(),
        session=FakeSession([FakeResponse(403, {"text": "Read denied"})]),
    )

    with pytest.raises(
        InfobloxApiError,
        match=r"API failed\nStatus code: 403\nDetail: Read denied",
    ):
        client.wapi_request("/network", method="get")


def test_unknown_http_error_keeps_legacy_fallback():
    client = InfobloxClient(Asset(), session=FakeSession([FakeResponse(418, {"text": "teapot"})]))

    with pytest.raises(
        InfobloxApiError,
        match=r"API failed\nStatus code: 418\nDetail: Unknown error occurred",
    ):
        client.wapi_request("/network", method="get")


def test_list_rpz_404_is_returned_as_action_specific_data():
    client = InfobloxClient(Asset(), session=FakeSession([FakeResponse(404, {"text": "missing view"})]))

    assert client.paged_request("/zone_rp", allow_not_found=True) == {
        "resource_not_found": True,
        "error_message": "missing view",
    }


def test_non_json_response_preserves_parse_error_behavior():
    client = InfobloxClient(
        Asset(),
        session=FakeSession([FakeResponse(200, {"ignored": True}, headers={"Content-Type": "text/plain"})]),
    )

    response = client.wapi_request("/network", method="get")
    assert response.data is None


def test_cookie_and_logout_retain_legacy_session_behavior():
    session = FakeSession([FakeResponse(200, {})])
    client = InfobloxClient(Asset(), session=session)

    client.use_session_cookie()
    client.logout()
    client.close()

    assert session.headers == {"ibapauth": "session-cookie"}
    assert session.calls[0][0] == "post"
    assert session.calls[0][1].endswith("/wapi/v2.3.1/logout")
    assert session.closed
