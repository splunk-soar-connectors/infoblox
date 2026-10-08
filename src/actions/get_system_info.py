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
"""get system info action implementation."""

import time
from typing import Any

from soar_sdk.abstract import SOARClient

from ..asset import Asset
from ..infoblox_client import DEFAULT_NETWORK_VIEW, InfobloxClient
from ._common import DATE_FORMAT, HOST_INFO_UNAVAILABLE, _is_address, _is_ipv6, _run_action
from ._models import GetSystemInfoParams, GetSystemInfoSummary


def _get_system_info_handler(client: InfobloxClient, params: GetSystemInfoParams) -> dict[str, Any]:
    hostname = params.ip_hostname
    network_view = params.network_view if params.network_view is not None else DEFAULT_NETWORK_VIEW
    lease_query: dict[str, Any] = {
        "_return_fields": (
            "binding_state,starts,ends,address,billing_class,client_hostname,tsfp,tstp,uid,"
            "remote_id,username,variable,cltt,hardware,network,network_view,option,protocol,"
            "served_by,server_host_name,billing_class,ipv6_duid,ipv6_iaid,ipv6_preferred_lifetime,"
            "ipv6_prefix_bits,is_invalid_mac,never_ends,never_starts,next_binding_state,on_commit,"
            "on_expiry,on_release"
        )
    }
    if _is_address(hostname) or _is_ipv6(hostname):
        lease_query["address"] = hostname
    else:
        lease_query["client_hostname"] = hostname
    lease_query["network_view"] = network_view
    lease_response = client.request("/lease", params=lease_query, method="get").data
    lease_rows = lease_response or []

    host_rows: list[dict[str, Any]] | None = None
    if network_view == DEFAULT_NETWORK_VIEW:
        is_ipv4 = _is_address(hostname) and ":" not in hostname
        is_ipv6 = _is_ipv6(hostname)
        if is_ipv4:
            host_endpoint = "/record:a"
            host_query = {
                "_return_fields": "ipv4addr,name,view,zone,discovered_data",
                "ipv4addr": hostname,
                "view": DEFAULT_NETWORK_VIEW,
            }
        elif is_ipv6:
            host_endpoint = "/record:aaaa"
            host_query = {
                "_return_fields": "ipv6addr,name,view,zone,discovered_data",
                "ipv6addr": hostname,
                "view": DEFAULT_NETWORK_VIEW,
            }
        else:
            host_endpoint = "/record:a"
            host_query = {
                "_return_fields": "ipv4addr,name,view,zone,discovered_data",
                "name~": hostname,
                "view": DEFAULT_NETWORK_VIEW,
            }
        host_rows = client.request(host_endpoint, params=host_query, method="get").data
        if not is_ipv4 and not is_ipv6 and not host_rows:
            host_query = {
                "_return_fields": "ipv6addr,name,view,zone,discovered_data",
                "name~": hostname,
                "view": DEFAULT_NETWORK_VIEW,
            }
            host_rows = client.request("/record:aaaa", params=host_query, method="get").data

    if not lease_rows and not host_rows:
        return {
            "success": True,
            "message": HOST_INFO_UNAVAILABLE,
            "data": [],
            "summary": {},
        }

    data: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}
    if not lease_rows and host_rows:
        for host in host_rows:
            name = host["name"]
            zone_suffix = f".{host['zone']}"
            if name.endswith(zone_suffix):
                name = name[: -len(zone_suffix)]
            if not (_is_address(hostname) or _is_ipv6(hostname)) and name != hostname:
                continue
            discovered = host.get("discovered_data") or {}
            item: dict[str, Any] = {
                "client_hostname": name,
                "hardware": discovered.get("mac_address"),
                "os": discovered.get("os"),
                "address": host.get("ipv4addr", host.get("ipv6addr")),
            }
            if host.get("ipv4addr"):
                item["protocol"] = "IPV4"
            elif host.get("ipv6addr"):
                item["protocol"] = "IPV6"
            summary["mac_address"] = item["hardware"]
            summary["is_static_ip"] = True
            data.append(item)

    for lease in lease_rows:
        if host_rows:
            matching_host = next(
                (host for host in host_rows if host.get("ipv4addr") == lease["address"] or host.get("ipv6addr") == lease["address"]),
                None,
            )
            if matching_host:
                lease["os"] = (matching_host.get("discovered_data") or {}).get("os")
        for time_key in ("cltt", "starts", "ends"):
            lease[time_key] = time.strftime(DATE_FORMAT, time.localtime(lease[time_key]))
        summary.update(
            {
                "mac_address": lease["hardware"],
                "binding_state": lease["binding_state"],
                "never_ends": lease["never_ends"],
                "is_static_ip": False,
            }
        )
        data.append(lease)

    if not data:
        return {
            "success": True,
            "message": HOST_INFO_UNAVAILABLE,
            "data": [],
            "summary": summary,
        }
    return {"success": True, "data": data, "summary": summary}


def get_system_info(params: GetSystemInfoParams, soar: SOARClient, asset: Asset):
    return _run_action(params, asset, soar, GetSystemInfoSummary, _get_system_info_handler)
