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
"""Legacy test-connectivity playbook action backed by the SDK app hook probe."""

from typing import Any

from soar_sdk.params import Params

from ..infoblox_client import DEFAULT_TIMEOUT, InfobloxApiError, InfobloxClient


def _test_connectivity_handler(client: InfobloxClient, _params: Params) -> dict[str, Any]:
    try:
        client.request("/?_schema", method="get", timeout=DEFAULT_TIMEOUT)
    except InfobloxApiError:
        return {"success": False, "message": "Connectivity test failed"}
    return {"success": True, "message": "Connectivity test succeeded"}
