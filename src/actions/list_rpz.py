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

from ..asset import Asset
from ..infoblox_client import DEFAULT_NETWORK_VIEW, InfobloxClient
from ._common import DATE_FORMAT, _run_action
from ._models import ListRpzParams, ListRpzSummary


def _list_rpz_handler(client: InfobloxClient, params: ListRpzParams) -> dict[str, Any]:
    view = params.network_view if params.network_view is not None else DEFAULT_NETWORK_VIEW
    rows = client.rpz_details({"view": view}, allow_not_found=True)
    if isinstance(rows, dict) and rows.get("resource_not_found"):
        return {
            "success": False,
            "message": rows.get("error_message", "This action gets the data from default network view only"),
        }
    total = len(rows)
    for row in rows:
        if row.get("rpz_last_updated_time"):
            row["rpz_last_updated_time"] = time.strftime(DATE_FORMAT, time.localtime(row["rpz_last_updated_time"]))
    return {
        "success": True,
        "data": rows,
        "summary": {"total_response_policy_zones": total},
    }


def list_rpz(params: ListRpzParams, soar: SOARClient, asset: Asset):
    return _run_action(params, asset, soar, ListRpzSummary, _list_rpz_handler)
