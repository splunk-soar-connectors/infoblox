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
"""list rpz action implementation."""

import time
from typing import Any

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param

from ..asset import Asset
from ..consts import (
    INFOBLOX_JSON_DATE_FORMAT,
    INFOBLOX_JSON_ERROR_MESSAGE,
    INFOBLOX_LAST_UPDATED_TIME,
    INFOBLOX_LIST_RPZ_NON_DEF_MESSAGE,
    INFOBLOX_NETWORK_VIEW_DEFAULT,
    INFOBLOX_RESOURCE_NOT_FOUND,
    INFOBLOX_TOTAL_RESPONSE_POLICY_ZONES,
)
from ..infoblox_client import InfobloxClient
from .common import NetworkViewParams, run_action


class ListRpzParams(NetworkViewParams):
    network_view: str | None = Param(
        description="Network view",
        default=INFOBLOX_NETWORK_VIEW_DEFAULT,
        primary=True,
        cef_types=["infoblox view"],
    )


class ListRpzOutput(ActionOutput):
    fqdn: str | None = OutputField(
        cef_types=["infoblox rpz"],
        example_values=["test_fqdn"],
        column_name="FQDN Of RPZ",
    )
    rpz_type: str | None = OutputField(example_values=["LOCAL"], column_name="Type")
    rpz_policy: str | None = OutputField(example_values=["GIVEN"], column_name="RPZ Policy Override")
    network_view: str | None = OutputField(
        cef_types=["infoblox view"],
        example_values=["default"],
        column_name="Network View",
    )
    rpz_severity: str | None = OutputField(example_values=["MAJOR"], column_name="Severity")
    rpz_priority: float | None = OutputField(example_values=[1], column_name="Priority")
    rpz_last_updated_time: str | None = OutputField(column_name="Last Updated")
    comment: str | None = OutputField(example_values=["Test comment"], column_name="Comment")
    ref: str | None = OutputField(alias="_ref", example_values=["zone_rp/AA1aAa1aaAaa1Aa1aAa:test/default"])
    disable: bool | None = None
    ns_group: str | None = OutputField(example_values=["PRIMARY"])
    primary_type: str | None = OutputField(example_values=["Grid"])
    substitute_name: str | None = OutputField(example_values=["test_name"])


class ListRpzSummary(ActionOutput):
    total_response_policy_zones: int | None = OutputField(example_values=[3])


def _list_rpz_handler(client: InfobloxClient, params: ListRpzParams) -> dict[str, Any]:
    # The Params default covers omitted inputs; preserve an explicit None.
    view = params.network_view
    rows = client.rpz_details({"view": view}, allow_not_found=True)
    if isinstance(rows, dict) and rows.get(INFOBLOX_RESOURCE_NOT_FOUND):
        return {
            "success": False,
            "message": rows.get(INFOBLOX_JSON_ERROR_MESSAGE, INFOBLOX_LIST_RPZ_NON_DEF_MESSAGE),
        }
    total = len(rows)
    for row in rows:
        if row.get(INFOBLOX_LAST_UPDATED_TIME):
            row[INFOBLOX_LAST_UPDATED_TIME] = time.strftime(INFOBLOX_JSON_DATE_FORMAT, time.localtime(row[INFOBLOX_LAST_UPDATED_TIME]))
    return {
        "success": True,
        "data": rows,
        "summary": {INFOBLOX_TOTAL_RESPONSE_POLICY_ZONES: total},
    }


def list_rpz(params: ListRpzParams, soar: SOARClient, asset: Asset):
    return run_action(params, asset, soar, ListRpzSummary, _list_rpz_handler)
