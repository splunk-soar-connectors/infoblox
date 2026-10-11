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
"""list network view action implementation."""

from typing import Any

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Params

from ..asset import Asset
from ..consts import INFOBLOX_NETWORK_VIEW, INFOBLOX_NETWORK_VIEW_INFO_UNAVAILABLE
from ..infoblox_client import InfobloxClient
from ._common import _run_action


class ListNetworkViewParams(Params):
    pass


class ListNetworkViewOutput(ActionOutput):
    ref: str | None = OutputField(
        alias="_ref",
        example_values=["networkview/AA1aAa1aaAaa1Aa1aAa:default/true"],
    )
    comment: str | None = OutputField(example_values=["Test comment"])
    name: str | None = OutputField(
        cef_types=["infoblox view"],
        example_values=["default"],
        column_name="Network View",
    )
    is_default: bool | None = OutputField(example_values=[True, False], column_name="Default")


class ListNetworkViewSummary(ActionOutput):
    total_network_view: int | None = OutputField(example_values=[2])


def _list_network_view_handler(client: InfobloxClient, _params: Params) -> dict[str, Any]:
    rows = client.paged_request(INFOBLOX_NETWORK_VIEW, method="get")
    if not rows:
        return {
            "success": False,
            "message": INFOBLOX_NETWORK_VIEW_INFO_UNAVAILABLE,
            "summary": {},
        }
    total = len(rows)
    return {
        "success": True,
        "data": rows,
        "summary": {"total_network_view": total},
    }


def list_network_view(params: ListNetworkViewParams, soar: SOARClient, asset: Asset):
    return _run_action(params, asset, soar, ListNetworkViewSummary, _list_network_view_handler)
