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
"""Shared response policy zone mutation logic."""

from typing import Any
from urllib.parse import urlsplit

from soar_sdk.params import Params

from ..consts import (
    INFOBLOX_BLOCK_DOMAIN_SUCCESS,
    INFOBLOX_BLOCK_IP_SUCCESS,
    INFOBLOX_DOMAIN_ALREADY_BLOCKED,
    INFOBLOX_DOMAIN_ALREADY_UNBLOCKED,
    INFOBLOX_DOMAIN_ENDPOINT,
    INFOBLOX_DOMAIN_EXISTS_NOT_IN_BLOCKED_STATE,
    INFOBLOX_DOMAIN_NOT_IN_BLOCKED_STATE,
    INFOBLOX_DOMAIN_UNBLOCK_SUCCESS,
    INFOBLOX_INVALID_DOMAIN_PARAMETER,
    INFOBLOX_IP_ALREADY_BLOCKED,
    INFOBLOX_IP_ALREADY_UNBLOCKED,
    INFOBLOX_IP_ENDPOINT,
    INFOBLOX_IP_EXISTS_NOT_IN_BLOCKED_STATE,
    INFOBLOX_IP_NOT_IN_BLOCKED_STATE,
    INFOBLOX_IP_UNBLOCK_SUCCESS,
    INFOBLOX_JSON_COMMENT,
    INFOBLOX_JSON_RECORD_NAME,
    INFOBLOX_JSON_REF,
    INFOBLOX_JSON_RP_ZONE,
    INFOBLOX_PARAM_CANONICAL,
    INFOBLOX_PARAM_FQDN,
    INFOBLOX_PARAM_VIEW,
    INFOBLOX_PARAM_ZONE,
    INFOBLOX_REFERENCE_LINK,
    INFOBLOX_RP_ZONE_NOT_EXISTS,
    INFOBLOX_RP_ZONE_POLICY_RULE_ERROR,
    INFOBLOX_RPZ_POLICY,
)
from ..infoblox_client import InfobloxApiError, InfobloxClient, exception_message


def _validate_rpz(client: InfobloxClient, rp_zone: str, network_view: str | None) -> list[dict[str, Any]]:
    rows = client.rpz_details({INFOBLOX_PARAM_FQDN: rp_zone, INFOBLOX_PARAM_VIEW: network_view}, allow_not_found=False)
    if not rows:
        raise InfobloxApiError(INFOBLOX_RP_ZONE_NOT_EXISTS.format(fqdn_name=rp_zone))
    policy = rows[0][INFOBLOX_RPZ_POLICY]
    if policy != "GIVEN":
        raise InfobloxApiError(INFOBLOX_RP_ZONE_POLICY_RULE_ERROR.format(rule_name=policy))
    return rows


def _normalize_domain(value: str) -> str:
    try:
        parsed = urlsplit(value)
        # Legacy stripped a URL to its hostname only when SOAR recognized it
        # as a URL; strings that merely contain :// stayed as domain input.
        if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
            if parsed.hostname:
                value = parsed.hostname
        return value.encode("idna").decode("utf-8")
    except Exception:
        # The legacy helper logged an encoding/parsing failure and kept the input.
        return value


def _ip_rule_action(
    client: InfobloxClient,
    params: Params,
    *,
    block: bool,
    comment: str | None = None,
) -> dict[str, Any]:
    ip_address = params.ip
    rp_zone = params.rp_zone
    # Each action Params model applies the legacy "default" when omitted.
    # Keep explicit None values unchanged, matching param.get(key, default).
    view = params.network_view
    rule_name = f"{ip_address.lower()}.{rp_zone}"
    endpoint = INFOBLOX_IP_ENDPOINT
    _validate_rpz(client, rp_zone, view)
    client.use_session_cookie()
    query = {INFOBLOX_JSON_RECORD_NAME: rule_name, INFOBLOX_PARAM_ZONE: rp_zone, INFOBLOX_PARAM_VIEW: view}
    response = client.request(endpoint, params=query, method="get").data
    existing = response or []

    if block:
        if existing:
            if existing[0].get(INFOBLOX_PARAM_CANONICAL) != "":
                return {
                    "success": False,
                    "message": INFOBLOX_IP_EXISTS_NOT_IN_BLOCKED_STATE,
                }
            return {"success": True, "message": INFOBLOX_IP_ALREADY_BLOCKED}
        payload = {INFOBLOX_JSON_RECORD_NAME: rule_name, INFOBLOX_JSON_RP_ZONE: rp_zone, INFOBLOX_PARAM_CANONICAL: "", INFOBLOX_PARAM_VIEW: view}
        if comment:
            payload[INFOBLOX_JSON_COMMENT] = comment
        # Preserve the legacy request shape: this POST sends its values as query parameters.
        created = client.request(endpoint, params=payload, method="post").data
        return {
            "success": True,
            "message": INFOBLOX_BLOCK_IP_SUCCESS,
            "data": [{INFOBLOX_REFERENCE_LINK: created}],
        }

    if not existing:
        return {"success": True, "message": INFOBLOX_IP_ALREADY_UNBLOCKED}
    if existing[0].get(INFOBLOX_PARAM_CANONICAL) != "":
        return {
            "success": False,
            "message": INFOBLOX_IP_NOT_IN_BLOCKED_STATE,
        }
    ref = existing[0].get(INFOBLOX_JSON_REF)
    deleted = client.request(f"/{ref}", method="delete").data
    return {
        "success": True,
        "message": INFOBLOX_IP_UNBLOCK_SUCCESS,
        "data": [{INFOBLOX_REFERENCE_LINK: deleted}],
    }


def _domain_rule_action(
    client: InfobloxClient,
    params: Params,
    *,
    block: bool,
    comment: str | None = None,
) -> dict[str, Any]:
    try:
        domain = _normalize_domain(params.domain)
    except Exception as error:
        return {
            "success": False,
            "message": INFOBLOX_INVALID_DOMAIN_PARAMETER.format(exception_message(error)),
        }
    rp_zone = params.rp_zone
    view = params.network_view
    rule_name = f"{domain}.{rp_zone}"
    endpoint = INFOBLOX_DOMAIN_ENDPOINT
    _validate_rpz(client, rp_zone, view)
    client.use_session_cookie()
    query = {INFOBLOX_JSON_RECORD_NAME: rule_name, INFOBLOX_PARAM_ZONE: rp_zone, INFOBLOX_PARAM_VIEW: view}
    response = client.request(endpoint, params=query, method="get").data
    existing = response or []

    if block:
        if existing:
            if existing[0].get(INFOBLOX_PARAM_CANONICAL) != "":
                return {
                    "success": False,
                    "message": INFOBLOX_DOMAIN_EXISTS_NOT_IN_BLOCKED_STATE,
                }
            return {"success": True, "message": INFOBLOX_DOMAIN_ALREADY_BLOCKED}
        payload = {INFOBLOX_JSON_RECORD_NAME: rule_name, INFOBLOX_JSON_RP_ZONE: rp_zone, INFOBLOX_PARAM_CANONICAL: "", INFOBLOX_PARAM_VIEW: view}
        if comment:
            payload[INFOBLOX_JSON_COMMENT] = comment
        created = client.request(endpoint, data=payload).data
        return {
            "success": True,
            "message": INFOBLOX_BLOCK_DOMAIN_SUCCESS,
            "data": [{INFOBLOX_REFERENCE_LINK: created}],
        }

    if not existing:
        return {"success": True, "message": INFOBLOX_DOMAIN_ALREADY_UNBLOCKED}
    if existing[0].get(INFOBLOX_PARAM_CANONICAL) != "":
        return {
            "success": False,
            "message": INFOBLOX_DOMAIN_NOT_IN_BLOCKED_STATE,
        }
    ref = existing[0].get(INFOBLOX_JSON_REF)
    deleted = client.request(f"/{ref}", method="delete").data
    return {
        "success": True,
        "message": INFOBLOX_DOMAIN_UNBLOCK_SUCCESS,
        "data": [{INFOBLOX_REFERENCE_LINK: deleted}],
    }
