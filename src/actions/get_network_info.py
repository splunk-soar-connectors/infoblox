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
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..consts import (
    INFOBLOX_IP_VALIDATION_FAILED,
    INFOBLOX_JSON_NETWORK,
    INFOBLOX_JSON_NETWORK_VIEW,
    INFOBLOX_NETWORK_ENDPOINT,
)
from ..infoblox_client import InfobloxClient
from .common import action_result, failed_outcome, is_ip, run_action


class GetNetworkInfoParams(Params):
    ip: str | None = Param(
        description="IP or IP network (CIDR notation)",
        required=False,
        primary=True,
        cef_types=["ip", "ipv6", "cidr"],
    )
    network_view: str | None = Param(
        description="Network view",
        required=False,
        primary=True,
        cef_types=["infoblox view"],
    )


class GetNetworkInfoOutput(ActionOutput):
    ref: str | None = OutputField(
        alias="_ref",
        example_values=["range/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:10.0.0.1/10.254.254.254/Internal%20Networks"],
    )
    network: str | None = OutputField(
        cef_types=["ip", "ipv6", "cidr"],
        example_values=["10.0.0.0/8"],
        column_name="Network",
    )
    network_view: str | None = OutputField(
        cef_types=["infoblox view"],
        example_values=["Internal Networks"],
        column_name="Network View",
    )
    comment: str | None = OutputField(example_values=["Example of a comment"], column_name="Comment")


class GetNetworkInfoSummary(ActionOutput):
    number_of_matching_networks: int | None = OutputField(example_values=[1])


def _get_network_info_handler(client: InfobloxClient, params: GetNetworkInfoParams) -> dict[str, Any]:
    search_ip: str | None = None
    query: dict[str, Any] = {}
    # Keep the legacy defensive check before using an IP as a search filter.
    if params.ip and is_ip(params.ip):
        if "/" in params.ip:
            query[INFOBLOX_JSON_NETWORK] = params.ip
        else:
            search_ip = params.ip
    if params.network_view:
        query[INFOBLOX_JSON_NETWORK_VIEW] = params.network_view

    rows = client.paged_request(INFOBLOX_NETWORK_ENDPOINT, params=query, method="get")
    matching_rows: list[dict[str, Any]] = []
    try:
        for row in rows:
            if search_ip:
                if ipaddress.ip_address(search_ip) in ipaddress.ip_network(row.get("network")):
                    matching_rows.append(row)
            else:
                matching_rows.append(row)
    except Exception as error:
        return failed_outcome(error, data=matching_rows)

    total = len(matching_rows)
    return {
        "success": True,
        "data": matching_rows,
        "summary": {"number_of_matching_networks": total},
    }


def get_network_info(params: GetNetworkInfoParams, soar: SOARClient, asset: Asset):
    if params.ip is not None and not is_ip(params.ip):
        return action_result(
            params,
            soar,
            GetNetworkInfoSummary,
            success=False,
            message=INFOBLOX_IP_VALIDATION_FAILED,
        )
    return run_action(params, asset, soar, GetNetworkInfoSummary, _get_network_info_handler)
