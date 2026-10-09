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
"""get network info action implementation."""

import ipaddress
from typing import Any

from soar_sdk.abstract import SOARClient

from ..asset import Asset
from ..infoblox_client import InfobloxClient
from ._common import _is_ip, _run_action
from ._models import GetNetworkInfoParams, GetNetworkInfoSummary


def _get_network_info_handler(client: InfobloxClient, params: GetNetworkInfoParams) -> dict[str, Any]:
    search_ip: str | None = None
    query: dict[str, Any] = {}
    # Keep the handler's legacy defensive check in addition to the SDK model
    # validator, which replaces the connector's global set_validator("ip", ...).
    if params.ip and _is_ip(params.ip):
        if "/" in params.ip:
            query["network"] = params.ip
        else:
            search_ip = params.ip
    if params.network_view:
        query["network_view"] = params.network_view

    rows = client.paged_request("/network", params=query, method="get")
    matching_rows: list[dict[str, Any]] = []
    for row in rows:
        if search_ip:
            if ipaddress.ip_address(search_ip) in ipaddress.ip_network(row.get("network")):
                matching_rows.append(row)
        else:
            matching_rows.append(row)

    total = len(matching_rows)
    return {
        "success": True,
        "data": matching_rows,
        "summary": {"number_of_matching_networks": total},
    }


def get_network_info(params: GetNetworkInfoParams, soar: SOARClient, asset: Asset):
    return _run_action(params, asset, soar, GetNetworkInfoSummary, _get_network_info_handler)
