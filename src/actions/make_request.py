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
"""make request action implementation."""

import json
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

import requests
from soar_sdk.action_results import MakeRequestOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import MakeRequestParams, Param

from ..asset import Asset
from ..infoblox_client import InfobloxClient, exception_message


class InfobloxMakeRequestParams(MakeRequestParams):
    """Make-request inputs with valid JSON examples in the action metadata."""

    headers: str = Param(
        description='The headers to send with the request (JSON object). An example is {"Content-Type": "application/json"}',
        required=False,
    )
    body: str = Param(
        description='The body to send with the request (JSON object). An example is {"key": "value", "key2": "value2"}',
        required=False,
    )


def _parse_json_object(value: str | None, field_name: str) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise ActionFailure(f"{field_name} must be a JSON object or query string") from error
    if not isinstance(parsed, dict):
        raise ActionFailure(f"{field_name} must be a JSON object")
    return parsed


def _validate_wapi_path(path: str) -> None:
    """Reject path syntax that could escape the versioned WAPI endpoint."""
    decoded_path = path
    while True:
        fully_decoded_path = unquote(decoded_path)
        if fully_decoded_path == decoded_path:
            break
        decoded_path = fully_decoded_path

    if "\\" in decoded_path or any(ord(character) < 0x20 or ord(character) == 0x7F for character in decoded_path):
        raise ActionFailure("endpoint path contains an invalid character")

    # Some HTTP servers treat semicolon suffixes as path parameters before
    # normalizing dot segments, so validate both plain and parameterized forms.
    if any(segment.split(";", 1)[0] in {".", ".."} for segment in decoded_path.split("/")):
        raise ActionFailure("endpoint path must not contain dot segments")


def make_request(params: InfobloxMakeRequestParams, asset: Asset) -> MakeRequestOutput:
    """Send an authenticated request to an Infoblox WAPI endpoint."""
    endpoint = params.endpoint.strip()
    parsed_endpoint = urlsplit(endpoint)
    if parsed_endpoint.scheme or parsed_endpoint.netloc:
        raise ActionFailure("endpoint must be a relative WAPI path")
    path = parsed_endpoint.path or "/"
    _validate_wapi_path(path)
    wapi_prefix = "/wapi/v2.3.1"
    if path == wapi_prefix:
        path = "/"
    elif path.startswith(f"{wapi_prefix}/"):
        path = path[len("/wapi/v2.3.1") :] or "/"
    elif path.startswith(wapi_prefix):
        raise ActionFailure("endpoint path has an invalid WAPI prefix")
    if not path.startswith("/"):
        path = f"/{path}"

    headers = _parse_json_object(params.headers, "headers")
    if params.query_parameters and params.query_parameters.lstrip().startswith("{"):
        query_parameters = parse_qsl(parsed_endpoint.query, keep_blank_values=True)
        query_parameters.extend(_parse_json_object(params.query_parameters, "query_parameters").items())
    else:
        query_text = params.query_parameters or ""
        if parsed_endpoint.query:
            query_text = "&".join(part for part in (parsed_endpoint.query, query_text.lstrip("?")) if part)
        query_parameters = parse_qsl(query_text.lstrip("?"), keep_blank_values=True)

    client = InfobloxClient(asset)
    try:
        verify_ssl = params.verify_ssl if "verify_ssl" in params.model_fields_set else client.verify_ssl
        response = client.session.request(
            params.http_method.upper(),
            f"{client.base_url}{path}",
            auth=client.auth,
            headers=headers,
            params=query_parameters,
            data=params.body or None,
            timeout=params.timeout,
            verify=verify_ssl,
        )
        return MakeRequestOutput(
            status_code=response.status_code,
            response_body=response.text,
        )
    except requests.RequestException as error:
        raise ActionFailure(f"Connection failed. {exception_message(error)}") from error
    finally:
        client.close()
