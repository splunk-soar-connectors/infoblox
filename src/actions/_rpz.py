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

from ..infoblox_client import DEFAULT_NETWORK_VIEW, InfobloxApiError, InfobloxClient, exception_message
from ._common import RPZ_NOT_FOUND, RPZ_POLICY_REQUIRED
from ._models import DomainRpzParams, IpRpzParams


def _validate_rpz(client: InfobloxClient, rp_zone: str, network_view: str) -> list[dict[str, Any]]:
    rows = client.rpz_details({"fqdn": rp_zone, "view": network_view}, allow_not_found=False)
    if not rows:
        raise InfobloxApiError(RPZ_NOT_FOUND.format(rp_zone))
    policy = rows[0]["rpz_policy"]
    if policy != "GIVEN":
        raise InfobloxApiError(RPZ_POLICY_REQUIRED.format(policy))
    return rows


def _normalize_domain(value: str) -> str:
    try:
        if "://" in value:
            parsed = urlsplit(value)
            if parsed.hostname:
                value = parsed.hostname
        return value.encode("idna").decode("utf-8")
    except Exception:
        # The legacy helper logged an encoding/parsing failure and kept the input.
        return value


def _ip_rule_action(
    client: InfobloxClient,
    params: IpRpzParams,
    *,
    block: bool,
    comment: str | None = None,
) -> dict[str, Any]:
    ip_address = params.ip
    rp_zone = params.rp_zone
    view = params.network_view if params.network_view is not None else DEFAULT_NETWORK_VIEW
    rule_name = f"{ip_address.lower()}.{rp_zone}"
    endpoint = "/record:rpz:cname:ipaddress"
    _validate_rpz(client, rp_zone, view)
    client.use_session_cookie()
    query = {"name": rule_name, "zone": rp_zone, "view": view}
    response = client.request(endpoint, params=query, method="get").data
    existing = response or []

    if block:
        if existing:
            if existing[0].get("canonical") != "":
                return {
                    "success": False,
                    "message": ("RPZ rule for specified IP already exists, But it is not of type 'Block IP Address (No Such Domain) Rule'"),
                }
            return {"success": True, "message": "IP/CIDR already blocked"}
        payload = {"name": rule_name, "rp_zone": rp_zone, "canonical": "", "view": view}
        if comment:
            payload["comment"] = comment
        # Preserve the legacy request shape: this POST sends its values as query parameters.
        created = client.request(endpoint, params=payload, method="post").data
        return {
            "success": True,
            "message": "IP/CIDR blocked successfully",
            "data": [{"reference_link": created}],
        }

    if not existing:
        return {"success": True, "message": "IP/CIDR already unblocked"}
    if existing[0].get("canonical") != "":
        return {
            "success": False,
            "message": ("RPZ rule for specified IP is not of type 'Block IP Address (No Such Domain) Rule'"),
        }
    ref = existing[0].get("_ref")
    deleted = client.request(f"/{ref}", method="delete").data
    return {
        "success": True,
        "message": "IP/CIDR unblocked successfully",
        "data": [{"reference_link": deleted}],
    }


def _domain_rule_action(
    client: InfobloxClient,
    params: DomainRpzParams,
    *,
    block: bool,
    comment: str | None = None,
) -> dict[str, Any]:
    try:
        domain = _normalize_domain(params.domain)
    except Exception as error:
        return {
            "success": False,
            "message": (f"Please provide a valid 'domain' parameter. {exception_message(error)}"),
        }
    rp_zone = params.rp_zone
    view = params.network_view if params.network_view is not None else DEFAULT_NETWORK_VIEW
    rule_name = f"{domain}.{rp_zone}"
    endpoint = "/record:rpz:cname"
    _validate_rpz(client, rp_zone, view)
    client.use_session_cookie()
    query = {"name": rule_name, "zone": rp_zone, "view": view}
    response = client.request(endpoint, params=query, method="get").data
    existing = response or []

    if block:
        if existing:
            if existing[0].get("canonical") != "":
                return {
                    "success": False,
                    "message": ("RPZ rule for specified domain already exists, But it is not of type 'Block Domain Name (No Such Domain) Rule'"),
                }
            return {"success": True, "message": "Domain already blocked"}
        payload = {"name": rule_name, "rp_zone": rp_zone, "canonical": "", "view": view}
        if comment:
            payload["comment"] = comment
        created = client.request(endpoint, data=payload).data
        return {
            "success": True,
            "message": "Domain blocked successfully",
            "data": [{"reference_link": created}],
        }

    if not existing:
        return {"success": True, "message": "Domain already unblocked"}
    if existing[0].get("canonical") != "":
        return {
            "success": False,
            "message": ("RPZ rule for specified domain is not of type 'Block Domain Name (No Such Domain) Rule'"),
        }
    ref = existing[0].get("_ref")
    deleted = client.request(f"/{ref}", method="delete").data
    return {
        "success": True,
        "message": "Domain unblocked successfully",
        "data": [{"reference_link": deleted}],
    }
