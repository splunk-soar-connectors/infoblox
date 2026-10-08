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
"""HTTP and WAPI helpers shared by the Infoblox SOAR actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests


WAPI_BASE = "/wapi/v2.3.1"
DEFAULT_NETWORK_VIEW = "default"
DEFAULT_TIMEOUT = 30
PAGE_SIZE = 1000
MAX_PAGE_COUNT = 100

RETURN_FIELDS = "_return_fields"
PAGING = "_paging"
RETURN_AS_OBJECT = "_return_as_object"
MAX_RESULTS = "_max_results"
PAGE_ID = "_page_id"

ERROR_MESSAGES = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not found",
    405: "Method not allowed",
    500: "Internal server error",
}

RPZ_FIELDS = (
    "rpz_policy,fqdn,rpz_severity,disable,rpz_type,primary_type,ns_group,network_view,rpz_priority,rpz_last_updated_time,comment,substitute_name"
)


class InfobloxApiError(Exception):
    """An API or transport failure formatted for legacy action messages."""


@dataclass
class ApiResponse:
    status_code: int
    data: Any
    content_type: str


def exception_message(error: Exception) -> str:
    """Match the legacy connector's exception-to-message formatting."""
    error_code: Any = None
    error_message: Any = "Error message unavailable. Please check the asset configuration and|or the action parameters."
    if hasattr(error, "args"):
        if len(error.args) > 1:
            error_code, error_message = error.args[0], error.args[1]
        elif len(error.args) == 1:
            error_message = error.args[0]
    if not error_code:
        return f"Error message: {error_message}"
    return f"Error code: {error_code}. Error message: {error_message}"


class InfobloxClient:
    """Thin requests wrapper preserving the legacy WAPI transport contract."""

    def __init__(self, asset: Any, session: requests.Session | None = None) -> None:
        self.base_url = f"{asset.url.rstrip('/')}{WAPI_BASE}"
        self.auth = (asset.username, asset.password)
        self.verify_ssl = asset.verify_server_cert if asset.verify_server_cert is not None else True
        self.session = session or requests.Session()

    def request(
        self,
        endpoint: str,
        *,
        method: str = "post",
        params: Any = None,
        data: Any = None,
        timeout: int | None = None,
        allow_not_found: bool = False,
    ) -> ApiResponse:
        """Call a relative WAPI endpoint and parse its response like the legacy app."""
        request_func = getattr(self.session, method.lower(), None)
        if request_func is None:
            raise InfobloxApiError(f"Unsupported method {method}")

        request_kwargs: dict[str, Any] = {
            "auth": self.auth,
            "params": params,
            "data": data,
            "verify": self.verify_ssl,
        }
        if timeout is not None:
            request_kwargs["timeout"] = timeout

        try:
            response = request_func(f"{self.base_url}{endpoint}", **request_kwargs)
        except Exception as error:
            raise InfobloxApiError(f"Connection failed. {exception_message(error)}") from error

        if allow_not_found and response.status_code == 404:
            try:
                response_json = response.json()
            except Exception:
                response_json = None
            response_data: dict[str, Any] = {"resource_not_found": True}
            if isinstance(response_json, dict):
                response_data["error_message"] = response_json.get("text")
            return ApiResponse(
                status_code=response.status_code,
                data=response_data,
                content_type=response.headers.get("Content-Type", ""),
            )

        if response.status_code in ERROR_MESSAGES:
            message = ERROR_MESSAGES[response.status_code]
            try:
                response_json = response.json()
                if isinstance(response_json, dict):
                    message = response_json.get("text", message)
            except Exception:
                pass
            raise InfobloxApiError(f"API failed\nStatus code: {response.status_code}\nDetail: {message}")

        try:
            content_type = response.headers["Content-Type"]
            response_data = response.json() if "json" in content_type else None
        except Exception as error:
            parse_message = f"Unable to parse the fields parameter into a dictionary.\nResponse text - {response.text}"
            raise InfobloxApiError(f"{parse_message}. {exception_message(error)}") from error

        if response.status_code in (200, 201):
            return ApiResponse(
                status_code=response.status_code,
                data=response_data,
                content_type=content_type,
            )

        raise InfobloxApiError(f"API failed\nStatus code: {response.status_code}\nDetail: Unknown error occurred")

    def paged_request(
        self,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        method: str = "get",
        allow_not_found: bool = False,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Fetch WAPI pages while protecting against a repeated page token."""
        first_page_params = dict(params or {})
        first_page_params.update(
            {
                PAGING: 1,
                RETURN_AS_OBJECT: 1,
                MAX_RESULTS: PAGE_SIZE,
            }
        )
        response = self.request(
            endpoint,
            params=first_page_params,
            method=method,
            allow_not_found=allow_not_found,
        )
        if response.data.get("resource_not_found"):
            return response.data

        page_data = response.data
        combined_results = page_data.get("result", [])
        next_page_id = page_data.get("next_page_id")
        page_params: dict[str, Any] = {
            PAGE_ID: next_page_id,
            PAGING: 1,
            RETURN_AS_OBJECT: 1,
        }
        seen_page_ids: set[Any] = set()
        page_count = 1

        while page_params.get(PAGE_ID) is not None:
            page_id = page_params[PAGE_ID]
            if page_count >= MAX_PAGE_COUNT:
                raise InfobloxApiError(f"Stopped pagination after the maximum of {MAX_PAGE_COUNT} pages")
            if page_id in seen_page_ids:
                raise InfobloxApiError("Stopped pagination because the server repeated next_page_id")
            seen_page_ids.add(page_id)
            page_count += 1
            response = self.request(
                endpoint,
                params=page_params,
                method=method,
                allow_not_found=allow_not_found,
            )
            if response.data.get("resource_not_found"):
                break
            page_data = response.data
            combined_results.extend(page_data.get("result", []))
            page_params[PAGE_ID] = page_data.get("next_page_id")

        return combined_results

    def rpz_details(
        self,
        filters: dict[str, Any] | None = None,
        *,
        allow_not_found: bool = False,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        params = dict(filters or {})
        params[RETURN_FIELDS] = RPZ_FIELDS
        return self.paged_request("/zone_rp", params=params, method="get", allow_not_found=allow_not_found)

    def use_session_cookie(self) -> None:
        """Retain the legacy ibapauth header used by RPZ create/delete calls."""
        self.session.headers.update({"ibapauth": self.session.cookies["ibapauth"]})

    def logout(self) -> None:
        self.request("/logout", method="post")

    def close(self) -> None:
        self.session.close()
