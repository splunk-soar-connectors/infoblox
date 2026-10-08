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
"""list hosts action implementation."""

from typing import Any

from soar_sdk.abstract import SOARClient
from soar_sdk.params import Params

from ..asset import Asset
from ..infoblox_client import InfobloxClient
from ._common import _run_action
from ._models import ListHostsParams, ListHostsSummary


def _list_hosts_handler(client: InfobloxClient, _params: Params) -> dict[str, Any]:
    ipv4 = client.paged_request(
        "/record:a",
        params={"_return_fields": "ipv4addr,name,view,zone"},
        method="get",
    )
    rows: list[dict[str, Any]] = []
    for host in ipv4:
        host["ip"] = host.pop("ipv4addr")
        zone_suffix = f".{host['zone']}"
        if host["name"].endswith(zone_suffix):
            host["name"] = host["name"][: -len(zone_suffix)]
        rows.append(host)

    ipv6 = client.paged_request(
        "/record:aaaa",
        params={"_return_fields": "ipv6addr,name,view,zone"},
        method="get",
    )
    for host in ipv6:
        host["ip"] = host.pop("ipv6addr")
        zone_suffix = f".{host['zone']}"
        if host["name"].endswith(zone_suffix):
            host["name"] = host["name"][: -len(zone_suffix)]
        rows.append(host)

    total = len(ipv4) + len(ipv6)
    return {
        "success": True,
        "data": rows,
        "summary": {"total_hosts": total},
    }


def list_hosts(params: ListHostsParams, soar: SOARClient, asset: Asset):
    return _run_action(params, asset, soar, ListHostsSummary, _list_hosts_handler)
