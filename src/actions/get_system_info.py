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
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.meta.actions import ActionMeta
from soar_sdk.params import Param
from soar_sdk.types import Action

from ..asset import Asset
from ..consts import (
    INFOBLOX_HOST_INFO_UNAVAILABLE,
    INFOBLOX_JSON_A_IP,
    INFOBLOX_JSON_AAAA_IP,
    INFOBLOX_JSON_ADDRESS,
    INFOBLOX_JSON_BINDING_STATE,
    INFOBLOX_JSON_CLIENT_HOSTNAME,
    INFOBLOX_JSON_CLTT,
    INFOBLOX_JSON_CONTEXT_NAME_SEARCH,
    INFOBLOX_JSON_DATE_FORMAT,
    INFOBLOX_JSON_DISCOVERED_DATA,
    INFOBLOX_JSON_ENDS,
    INFOBLOX_JSON_HARDWARE,
    INFOBLOX_JSON_IS_STATIC_IP,
    INFOBLOX_JSON_MAC_ADDRESS,
    INFOBLOX_JSON_NETWORK_VIEW,
    INFOBLOX_JSON_NEVER_ENDS,
    INFOBLOX_JSON_OS,
    INFOBLOX_JSON_PROTOCOL,
    INFOBLOX_JSON_RECORD_NAME,
    INFOBLOX_JSON_RETURN_FIELDS,
    INFOBLOX_JSON_STARTS,
    INFOBLOX_LEASE,
    INFOBLOX_LEASE_RETURN_FIELDS,
    INFOBLOX_NETWORK_VIEW_DEFAULT,
    INFOBLOX_PARAM_VIEW,
    INFOBLOX_PARAM_ZONE,
    INFOBLOX_PROTOCOL_IPV4,
    INFOBLOX_PROTOCOL_IPV6,
    INFOBLOX_RECORD_A_RETURN_FIELDS,
    INFOBLOX_RECORD_AAAA_RETURN_FIELDS,
    INFOBLOX_RECORDS_IPv4_ENDPOINT,
    INFOBLOX_RECORDS_IPv6_ENDPOINT,
)
from ..infoblox_client import InfobloxClient
from .common import NetworkViewParams, is_address, is_ipv6, run_action


_TABLE_COLUMN_ORDERS = {
    "action_result.parameter.network_view": 9,
    "action_result.data.*.address": 0,
    "action_result.data.*.client_hostname": 1,
    "action_result.data.*.server_host_name": 2,
    "action_result.data.*.os": 3,
    "action_result.data.*.binding_state": 4,
    "action_result.data.*.starts": 5,
    "action_result.data.*.ends": 6,
    "action_result.data.*.cltt": 7,
    "action_result.data.*.network": 8,
    "action_result.data.*.served_by": 10,
}


class GetSystemInfoMeta(ActionMeta):
    """Keep this action's declared table column order in generated metadata."""

    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        metadata = super().model_dump(*args, **kwargs)
        for field in metadata.get("output", []):
            if (column_order := _TABLE_COLUMN_ORDERS.get(field["data_path"])) is not None:
                field["column_order"] = column_order
        return metadata


def apply_table_column_order(action: Action) -> None:
    """Apply the action-specific table column order supported by its output contract."""
    meta = action.meta
    action.meta = GetSystemInfoMeta(**{name: getattr(meta, name) for name in ActionMeta.model_fields})


class GetSystemInfoParams(NetworkViewParams):
    ip_hostname: str = Param(
        description="IP/Hostname",
        required=True,
        primary=True,
        cef_types=["ip", "host name"],
    )
    network_view: str | None = Param(
        description="Network view",
        default=INFOBLOX_NETWORK_VIEW_DEFAULT,
        primary=True,
        cef_types=["infoblox view"],
        column_name="Network View",
    )


class GetSystemInfoOutput(ActionOutput):
    # Declare table fields in legacy column order. Other raw WAPI fields follow.
    address: str | None = OutputField(cef_types=["ip"], example_values=["10.0.0.5"], column_name="Host IP")
    client_hostname: str | None = OutputField(cef_types=["host name"], column_name="Client Host Name")
    server_host_name: str | None = OutputField(
        cef_types=["host name"],
        example_values=["test-01.lab.test.local"],
        column_name="Server Host Name",
    )
    os: str | None = OutputField(example_values=["Linux"], column_name="OS")
    binding_state: str | None = OutputField(example_values=["FREE"], column_name="Binding State")
    starts: str | None = OutputField(example_values=["2010-10-10 10:11:12"], column_name="Starts")
    ends: str | None = OutputField(example_values=["2010-10-10 12:11:12"], column_name="Ends")
    cltt: str | None = OutputField(
        example_values=["2010-10-10 10:11:12"],
        column_name="Client Last Transaction Time",
    )
    network: str | None = OutputField(column_name="Network")
    ref: str | None = OutputField(
        alias="_ref",
        example_values=["lease/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:10.0.0.5/default"],
    )
    billing_class: str | None = None
    hardware: str | None = OutputField(cef_types=["mac address"], example_values=["0a:10:10:a0:a0:10"])
    ipv6_duid: str | None = None
    ipv6_iaid: str | None = None
    ipv6_preferred_lifetime: float | None = OutputField(example_values=[604800])
    ipv6_prefix_bits: float | None = OutputField(example_values=[48])
    is_invalid_mac: bool | None = None
    network_view: str | None = OutputField(cef_types=["infoblox view"], example_values=["default"])
    never_ends: bool | None = None
    never_starts: bool | None = None
    next_binding_state: str | None = OutputField(example_values=["ACTIVE"])
    on_commit: str | None = None
    on_expiry: str | None = None
    on_release: str | None = None
    option: str | None = None
    protocol: str | None = OutputField(example_values=["IPV4"])
    remote_id: str | None = None
    served_by: str | None = OutputField(cef_types=["ip"], example_values=["10.0.0.7"], column_name="Served By")
    tsfp: str | None = OutputField(example_values=["1504274705"])
    tstp: str | None = OutputField(example_values=["1504274905"])
    uid: str | None = None
    username: str | None = None
    variable: str | None = OutputField(example_values=['lt="undefined"'])


class GetSystemInfoSummary(ActionOutput):
    binding_state: str | None = None
    is_static_ip: bool | None = OutputField(example_values=[True, False])
    mac_address: str | None = OutputField(cef_types=["mac address"], example_values=["0a:10:10:a0:a0:10"])
    never_ends: bool | None = OutputField(example_values=[True, False])


def _get_system_info_handler(client: InfobloxClient, params: GetSystemInfoParams) -> dict[str, Any]:
    hostname = params.ip_hostname
    # Params already supplies the legacy default when the input is omitted.
    # Keep an explicitly supplied None intact, as the legacy connector did.
    network_view = params.network_view
    lease_query: dict[str, Any] = {INFOBLOX_JSON_RETURN_FIELDS: INFOBLOX_LEASE_RETURN_FIELDS}
    if is_address(hostname) or is_ipv6(hostname):
        lease_query[INFOBLOX_JSON_ADDRESS] = hostname
    else:
        lease_query[INFOBLOX_JSON_CLIENT_HOSTNAME] = hostname
    lease_query[INFOBLOX_JSON_NETWORK_VIEW] = network_view
    lease_response = client.wapi_request(INFOBLOX_LEASE, params=lease_query, method="get").data
    lease_rows = lease_response or []

    host_rows: list[dict[str, Any]] | None = None
    if network_view == INFOBLOX_NETWORK_VIEW_DEFAULT:
        is_ipv4 = is_address(hostname) and ":" not in hostname
        hostname_is_ipv6 = is_ipv6(hostname)
        if is_ipv4:
            host_endpoint = INFOBLOX_RECORDS_IPv4_ENDPOINT
            host_query = {
                INFOBLOX_JSON_RETURN_FIELDS: INFOBLOX_RECORD_A_RETURN_FIELDS,
                INFOBLOX_JSON_A_IP: hostname,
                INFOBLOX_PARAM_VIEW: INFOBLOX_NETWORK_VIEW_DEFAULT,
            }
        elif hostname_is_ipv6:
            host_endpoint = INFOBLOX_RECORDS_IPv6_ENDPOINT
            host_query = {
                INFOBLOX_JSON_RETURN_FIELDS: INFOBLOX_RECORD_AAAA_RETURN_FIELDS,
                INFOBLOX_JSON_AAAA_IP: hostname,
                INFOBLOX_PARAM_VIEW: INFOBLOX_NETWORK_VIEW_DEFAULT,
            }
        else:
            host_endpoint = INFOBLOX_RECORDS_IPv4_ENDPOINT
            host_query = {
                INFOBLOX_JSON_RETURN_FIELDS: INFOBLOX_RECORD_A_RETURN_FIELDS,
                INFOBLOX_JSON_CONTEXT_NAME_SEARCH: hostname,
                INFOBLOX_PARAM_VIEW: INFOBLOX_NETWORK_VIEW_DEFAULT,
            }
        host_rows = client.wapi_request(host_endpoint, params=host_query, method="get").data
        if not is_ipv4 and not is_ipv6 and not host_rows:
            host_query = {
                INFOBLOX_JSON_RETURN_FIELDS: INFOBLOX_RECORD_AAAA_RETURN_FIELDS,
                INFOBLOX_JSON_CONTEXT_NAME_SEARCH: hostname,
                INFOBLOX_PARAM_VIEW: INFOBLOX_NETWORK_VIEW_DEFAULT,
            }
            host_rows = client.wapi_request(INFOBLOX_RECORDS_IPv6_ENDPOINT, params=host_query, method="get").data

    if not lease_rows and not host_rows:
        return {
            "success": True,
            "message": INFOBLOX_HOST_INFO_UNAVAILABLE,
            "data": [],
            "summary": {},
        }

    data: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}
    if not lease_rows and host_rows:
        for host in host_rows:
            name = host[INFOBLOX_JSON_RECORD_NAME]
            zone_suffix = f".{host[INFOBLOX_PARAM_ZONE]}"
            if name.endswith(zone_suffix):
                name = name[: -len(zone_suffix)]
            if not (is_address(hostname) or is_ipv6(hostname)) and name != hostname:
                continue
            # Match legacy get(..., {}) semantics: a missing field is empty,
            # while an explicitly malformed None value still raises on .get.
            discovered = host.get(INFOBLOX_JSON_DISCOVERED_DATA, {})
            item: dict[str, Any] = {
                INFOBLOX_JSON_CLIENT_HOSTNAME: name,
                INFOBLOX_JSON_HARDWARE: discovered.get(INFOBLOX_JSON_MAC_ADDRESS),
                INFOBLOX_JSON_OS: discovered.get(INFOBLOX_JSON_OS),
                INFOBLOX_JSON_ADDRESS: host.get(INFOBLOX_JSON_A_IP, host.get(INFOBLOX_JSON_AAAA_IP)),
            }
            if host.get(INFOBLOX_JSON_A_IP) and is_address(host[INFOBLOX_JSON_A_IP]):
                item[INFOBLOX_JSON_PROTOCOL] = INFOBLOX_PROTOCOL_IPV4
            elif host.get(INFOBLOX_JSON_AAAA_IP) and is_address(host[INFOBLOX_JSON_AAAA_IP]):
                item[INFOBLOX_JSON_PROTOCOL] = INFOBLOX_PROTOCOL_IPV6
            summary[INFOBLOX_JSON_MAC_ADDRESS] = item[INFOBLOX_JSON_HARDWARE]
            summary[INFOBLOX_JSON_IS_STATIC_IP] = True
            data.append(item)

    for lease in lease_rows:
        if host_rows:
            matching_host = next(
                (
                    host
                    for host in host_rows
                    if host[INFOBLOX_JSON_A_IP] == lease[INFOBLOX_JSON_ADDRESS] or host[INFOBLOX_JSON_AAAA_IP] == lease[INFOBLOX_JSON_ADDRESS]
                ),
                None,
            )
            if matching_host:
                lease[INFOBLOX_JSON_OS] = matching_host.get(INFOBLOX_JSON_DISCOVERED_DATA, {}).get(INFOBLOX_JSON_OS)
        for time_key in (INFOBLOX_JSON_CLTT, INFOBLOX_JSON_STARTS, INFOBLOX_JSON_ENDS):
            lease[time_key] = time.strftime(INFOBLOX_JSON_DATE_FORMAT, time.localtime(lease[time_key]))
        summary.update(
            {
                INFOBLOX_JSON_MAC_ADDRESS: lease[INFOBLOX_JSON_HARDWARE],
                INFOBLOX_JSON_BINDING_STATE: lease[INFOBLOX_JSON_BINDING_STATE],
                INFOBLOX_JSON_NEVER_ENDS: lease[INFOBLOX_JSON_NEVER_ENDS],
                INFOBLOX_JSON_IS_STATIC_IP: False,
            }
        )
        data.append(lease)

    if not data:
        return {
            "success": True,
            "message": INFOBLOX_HOST_INFO_UNAVAILABLE,
            "data": [],
            "summary": summary,
        }
    return {"success": True, "data": data, "summary": summary}


def get_system_info(params: GetSystemInfoParams, soar: SOARClient, asset: Asset):
    return run_action(params, asset, soar, GetSystemInfoSummary, _get_system_info_handler)
