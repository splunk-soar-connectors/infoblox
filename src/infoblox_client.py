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

import httpx
from soar_sdk.auth import BasicAuth
from soar_sdk.logging import getLogger

from .consts import (
    INFOBLOX_BASE_ENDPOINT,
    INFOBLOX_ERROR_FROM_SERVER,
    INFOBLOX_ERROR_JSON_PARSE,
    INFOBLOX_ERROR_MESSAGE_UNAVAILABLE,
    INFOBLOX_ERROR_SERVER_CONNECTION,
    INFOBLOX_JSON_CONTENT_TYPE,
    INFOBLOX_JSON_ERROR_MESSAGE,
    INFOBLOX_JSON_MAX_RESULTS,
    INFOBLOX_JSON_NEXT_PAGE_ID,
    INFOBLOX_JSON_PAGE_ID,
    INFOBLOX_JSON_PAGING,
    INFOBLOX_JSON_RESULT,
    INFOBLOX_JSON_RETURN_AS_OBJECT,
    INFOBLOX_JSON_RETURN_FIELDS,
    INFOBLOX_JSON_TEXT,
    INFOBLOX_LIST_RP_ZONE_PARAMS,
    INFOBLOX_LOGOUT,
    INFOBLOX_MAX_PAGE_COUNT,
    INFOBLOX_PAGE_COUNT,
    INFOBLOX_PAGE_SIZE,
    INFOBLOX_PAGINATION_MAX_ERROR_FORMAT,
    INFOBLOX_PAGINATION_REPEAT_ERROR,
    INFOBLOX_RESOURCE_NOT_FOUND,
    INFOBLOX_REST_RESP_OTHER_ERROR_MESSAGE,
    INFOBLOX_REST_RESPONSE_MESSAGES,
    INFOBLOX_RP_ZONE_DETAILS_ENDPOINT,
)


logger = getLogger()


class InfobloxApiError(Exception):
    """An API or transport failure formatted for legacy action messages."""


@dataclass
class ApiResponse:
    data: Any


def exception_message(error: Exception) -> str:
    """Match the legacy connector's exception-to-message formatting."""
    error_code: Any = None
    error_message: Any = INFOBLOX_ERROR_MESSAGE_UNAVAILABLE
    if hasattr(error, "args"):
        if len(error.args) > 1:
            error_code, error_message = error.args[0], error.args[1]
        elif len(error.args) == 1:
            error_message = error.args[0]
    if not error_code:
        return f"Error message: {error_message}"
    return f"Error code: {error_code}. Error message: {error_message}"


class InfobloxClient:
    """Thin HTTPX wrapper preserving the legacy WAPI transport contract."""

    def __init__(self, asset: Any, session: httpx.Client | None = None) -> None:
        self.base_url = f"{asset.url.rstrip('/')}{INFOBLOX_BASE_ENDPOINT}"
        self.auth = BasicAuth(asset.username, asset.password)
        self.verify_ssl = asset.verify_server_cert if asset.verify_server_cert is not None else True
        # Requests has no default timeout and follows redirects for each request.
        self.session = session or httpx.Client(verify=self.verify_ssl, timeout=None, follow_redirects=True)

    def request(
        self,
        endpoint: str,
        *,
        method: str = "post",
        params: Any = None,
        data: Any = None,
        headers: dict[str, str] | None = None,
        timeout: int | None = None,
        verify_ssl: bool | None = None,
    ) -> httpx.Response:
        """Send an authenticated HTTP request to a relative WAPI endpoint."""
        if getattr(self.session, method.lower(), None) is None:
            raise InfobloxApiError(f"Unsupported method {method}")

        request_kwargs: dict[str, Any] = {
            "auth": self.auth,
            "params": params,
            "data": data,
        }
        if headers is not None:
            request_kwargs["headers"] = headers
        if timeout is not None:
            request_kwargs["timeout"] = timeout

        # HTTPX configures TLS verification on the client, while make_request
        # allows an action-level override. Use a short-lived client only when
        # that override differs, carrying the existing session headers/cookies
        # across so WAPI authentication remains consistent.
        request_verify = self.verify_ssl if verify_ssl is None else verify_ssl
        if request_verify == self.verify_ssl:
            return self.session.request(method.upper(), f"{self.base_url}{endpoint}", **request_kwargs)

        with httpx.Client(
            verify=request_verify,
            timeout=None,
            follow_redirects=True,
            headers=self.session.headers,
        ) as override_session:
            override_session.cookies.update(self.session.cookies)
            response = override_session.request(method.upper(), f"{self.base_url}{endpoint}", **request_kwargs)
            self.session.cookies.update(override_session.cookies)
            return response

    def wapi_request(
        self,
        endpoint: str,
        *,
        method: str = "post",
        params: Any = None,
        data: Any = None,
        timeout: int | None = None,
        allow_not_found: bool = False,
    ) -> ApiResponse:
        """Parse a WAPI response and apply the connector's legacy error behavior."""
        try:
            response = self.request(endpoint, method=method, params=params, data=data, timeout=timeout)
        except InfobloxApiError:
            raise
        except Exception as error:
            raise InfobloxApiError(f"{INFOBLOX_ERROR_SERVER_CONNECTION}. {exception_message(error)}") from error

        if allow_not_found and response.status_code == 404:
            try:
                response_json = response.json()
            except Exception:
                response_json = None
            response_data: dict[str, Any] = {INFOBLOX_RESOURCE_NOT_FOUND: True}
            if isinstance(response_json, dict):
                response_data[INFOBLOX_JSON_ERROR_MESSAGE] = response_json.get(INFOBLOX_JSON_TEXT)
            return ApiResponse(data=response_data)

        if response.status_code in INFOBLOX_REST_RESPONSE_MESSAGES:
            message = INFOBLOX_REST_RESPONSE_MESSAGES[response.status_code]
            try:
                response_json = response.json()
                if isinstance(response_json, dict):
                    message = response_json.get(INFOBLOX_JSON_TEXT, message)
            except Exception:
                pass
            raise InfobloxApiError(INFOBLOX_ERROR_FROM_SERVER.format(status=response.status_code, detail=message))

        try:
            content_type = response.headers[INFOBLOX_JSON_CONTENT_TYPE]
            response_data = response.json() if "json" in content_type else None
        except Exception as error:
            parse_message = INFOBLOX_ERROR_JSON_PARSE.format(raw_text=response.text)
            raise InfobloxApiError(f"{parse_message}. {exception_message(error)}") from error

        if response.status_code in (200, 201):
            return ApiResponse(data=response_data)

        raise InfobloxApiError(INFOBLOX_ERROR_FROM_SERVER.format(status=response.status_code, detail=INFOBLOX_REST_RESP_OTHER_ERROR_MESSAGE))

    def paged_request(
        self,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        method: str = "get",
        allow_not_found: bool = False,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Fetch WAPI pages while protecting against a repeated page token."""
        page_count = 1
        logger.debug(INFOBLOX_PAGE_COUNT.format(page_count))
        first_page_params = dict(params or {})
        first_page_params.update(
            {
                INFOBLOX_JSON_PAGING: 1,
                INFOBLOX_JSON_RETURN_AS_OBJECT: 1,
                INFOBLOX_JSON_MAX_RESULTS: INFOBLOX_PAGE_SIZE,
            }
        )
        response = self.wapi_request(
            endpoint,
            params=first_page_params,
            method=method,
            allow_not_found=allow_not_found,
        )
        if response.data.get(INFOBLOX_RESOURCE_NOT_FOUND):
            return response.data

        page_data = response.data
        combined_results = page_data.get(INFOBLOX_JSON_RESULT, [])
        next_page_id = page_data.get(INFOBLOX_JSON_NEXT_PAGE_ID)
        page_params: dict[str, Any] = {
            INFOBLOX_JSON_PAGE_ID: next_page_id,
            INFOBLOX_JSON_PAGING: 1,
            INFOBLOX_JSON_RETURN_AS_OBJECT: 1,
        }
        seen_page_ids: set[Any] = set()

        while page_params.get(INFOBLOX_JSON_PAGE_ID) is not None:
            page_id = page_params[INFOBLOX_JSON_PAGE_ID]
            if page_count >= INFOBLOX_MAX_PAGE_COUNT:
                raise InfobloxApiError(INFOBLOX_PAGINATION_MAX_ERROR_FORMAT.format(max_pages=INFOBLOX_MAX_PAGE_COUNT))
            if page_id in seen_page_ids:
                raise InfobloxApiError(INFOBLOX_PAGINATION_REPEAT_ERROR)
            seen_page_ids.add(page_id)
            page_count += 1
            logger.debug(INFOBLOX_PAGE_COUNT.format(page_count))
            response = self.wapi_request(
                endpoint,
                params=page_params,
                method=method,
                allow_not_found=allow_not_found,
            )
            if response.data.get(INFOBLOX_RESOURCE_NOT_FOUND):
                break
            page_data = response.data
            combined_results.extend(page_data.get(INFOBLOX_JSON_RESULT, []))
            page_params[INFOBLOX_JSON_PAGE_ID] = page_data.get(INFOBLOX_JSON_NEXT_PAGE_ID)

        return combined_results

    def rpz_details(
        self,
        filters: dict[str, Any] | None = None,
        *,
        allow_not_found: bool = False,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        params = dict(filters or {})
        params[INFOBLOX_JSON_RETURN_FIELDS] = INFOBLOX_LIST_RP_ZONE_PARAMS
        return self.paged_request(
            INFOBLOX_RP_ZONE_DETAILS_ENDPOINT,
            params=params,
            method="get",
            allow_not_found=allow_not_found,
        )

    def use_session_cookie(self) -> None:
        """Retain the legacy ibapauth header used by RPZ create/delete calls."""
        self.session.headers.update({"ibapauth": self.session.cookies["ibapauth"]})

    def logout(self) -> None:
        self.wapi_request(INFOBLOX_LOGOUT, method="post")

    def close(self) -> None:
        self.session.close()
