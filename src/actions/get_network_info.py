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

from pydantic import field_validator
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..consts import INFOBLOX_JSON_NETWORK_VIEW, INFOBLOX_NETWORK_ENDPOINT
from ..infoblox_client import InfobloxClient
from ._common import _is_ip, _run_action


class GetNetworkInfoParams(Params):
    ip: str | None = Param(
        description="IP or IP network (CIDR notation)",
        required=False,
        primary=True,
        cef_types=["ip"],
    )
    network_view: str | None = Param(
        description="Network view",
        required=False,
        primary=True,
        cef_types=["infoblox view"],
    )

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str | None) -> str | None:
        # The legacy global validator skipped omitted optional parameters.
        if value is not None and not _is_ip(value):
            raise ValueError("parameter 'ip' validation failed")
        return value


class GetNetworkInfoOutput(ActionOutput):
    ref: str | None = OutputField(
        alias="_ref",
        example_values=["range/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:10.0.0.1/10.254.254.254/Internal%20Networks"],
    )
    network: str | None = OutputField(
        cef_types=["ip"],
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
    # Keep the handler's legacy defensive check in addition to the SDK model
    # validator, which replaces the connector's global set_validator("ip", ...).
    if params.ip and _is_ip(params.ip):
        if "/" in params.ip:
            query["network"] = params.ip
        else:
            search_ip = params.ip
    if params.network_view:
        query[INFOBLOX_JSON_NETWORK_VIEW] = params.network_view

    rows = client.paged_request(INFOBLOX_NETWORK_ENDPOINT, params=query, method="get")
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
