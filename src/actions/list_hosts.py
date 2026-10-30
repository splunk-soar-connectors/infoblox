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
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Params

from ..asset import Asset
from ..consts import (
    INFOBLOX_HOST_IPV6_RETURN_FIELDS,
    INFOBLOX_HOST_RETURN_FIELDS,
    INFOBLOX_JSON_A_IP,
    INFOBLOX_JSON_AAAA_IP,
    INFOBLOX_JSON_IP,
    INFOBLOX_JSON_RECORD_NAME,
    INFOBLOX_JSON_RETURN_FIELDS,
    INFOBLOX_PARAM_ZONE,
    INFOBLOX_TOTAL_HOSTS,
    INFOBLOX_RECORDS_IPv4_ENDPOINT,
    INFOBLOX_RECORDS_IPv6_ENDPOINT,
)
from ..infoblox_client import InfobloxClient
from .common import failed_outcome, run_action


class DiscoveredDataOutput(ActionOutput):
    first_discovered: float | None = OutputField(example_values=[1495071666])
    last_discovered: float | None = OutputField(example_values=[1495071666])
    mac_address: str | None = OutputField(cef_types=["mac address"], example_values=["0a:10:10:a0:a0:10"])
    os: str | None = OutputField(example_values=["Linux"])


class ListHostsOutput(ActionOutput):
    ip: str | None = OutputField(cef_types=["ip", "ipv6"], example_values=["10.0.0.5"], column_name="IP")
    name: str | None = OutputField(cef_types=["host name"], example_values=["test"], column_name="Host Name")
    view: str | None = OutputField(
        cef_types=["infoblox view"],
        example_values=["External DNS"],
        column_name="Network View",
    )
    zone: str | None = OutputField(example_values=["example.com"], column_name="DNS Zone")
    ref: str | None = OutputField(
        alias="_ref",
        example_values=["record:a/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:test_nv_a_record.test_zone/default.dns"],
    )
    discovered_data: DiscoveredDataOutput | None = None


class ListHostsSummary(ActionOutput):
    total_hosts: int | None = OutputField(example_values=[1122])


class ListHostsParams(Params):
    pass


def _list_hosts_handler(client: InfobloxClient, _params: Params) -> dict[str, Any]:
    ipv4 = client.paged_request(
        INFOBLOX_RECORDS_IPv4_ENDPOINT,
        params={INFOBLOX_JSON_RETURN_FIELDS: INFOBLOX_HOST_RETURN_FIELDS},
        method="get",
    )
    rows: list[dict[str, Any]] = []
    try:
        for host in ipv4:
            host[INFOBLOX_JSON_IP] = host.pop(INFOBLOX_JSON_A_IP)
            zone_suffix = f".{host[INFOBLOX_PARAM_ZONE]}"
            if host[INFOBLOX_JSON_RECORD_NAME].endswith(zone_suffix):
                host[INFOBLOX_JSON_RECORD_NAME] = host[INFOBLOX_JSON_RECORD_NAME][: -len(zone_suffix)]
            rows.append(host)

        ipv6 = client.paged_request(
            INFOBLOX_RECORDS_IPv6_ENDPOINT,
            params={INFOBLOX_JSON_RETURN_FIELDS: INFOBLOX_HOST_IPV6_RETURN_FIELDS},
            method="get",
        )
        for host in ipv6:
            host[INFOBLOX_JSON_IP] = host.pop(INFOBLOX_JSON_AAAA_IP)
            zone_suffix = f".{host[INFOBLOX_PARAM_ZONE]}"
            if host[INFOBLOX_JSON_RECORD_NAME].endswith(zone_suffix):
                host[INFOBLOX_JSON_RECORD_NAME] = host[INFOBLOX_JSON_RECORD_NAME][: -len(zone_suffix)]
            rows.append(host)
    except Exception as error:
        return failed_outcome(error, data=rows)

    total = len(ipv4) + len(ipv6)
    return {
        "success": True,
        "data": rows,
        "summary": {INFOBLOX_TOTAL_HOSTS: total},
    }


def list_hosts(params: ListHostsParams, soar: SOARClient, asset: Asset):
    return run_action(params, asset, soar, ListHostsSummary, _list_hosts_handler)
