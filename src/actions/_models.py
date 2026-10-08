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
"""Parameter and output metadata for the Infoblox actions."""

from typing import Any

from pydantic import field_validator
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..infoblox_client import DEFAULT_NETWORK_VIEW
from ._common import _is_ip


class EmptyOutput(ActionOutput):
    """Metadata placeholder for the legacy connectivity action."""


class EmptySummary(ActionOutput):
    """Preserve the legacy connectivity action's empty summary."""


class LegacyStringSummary(ActionOutput):
    """Legacy RPZ mutation actions exposed the empty summary as a string path."""

    @classmethod
    def _to_json_schema(
        cls,
        parent_datapath: str = "action_result.summary",
        column_order_counter: Any = None,
    ):
        yield {"data_path": parent_datapath, "data_type": "string"}


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
        if value and not _is_ip(value):
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


class GetSystemInfoParams(Params):
    ip_hostname: str = Param(
        description="IP/Hostname",
        required=True,
        primary=True,
        cef_types=["ip", "host name"],
    )
    network_view: str | None = Param(
        description="Network view",
        default=DEFAULT_NETWORK_VIEW,
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


class IpRpzParams(Params):
    ip: str = Param(
        description="IP/CIDR to unblock",
        required=True,
        primary=True,
        cef_types=["ip"],
        column_name="IP",
    )
    rp_zone: str = Param(
        description="FQDN of response policy zone",
        required=True,
        primary=True,
        cef_types=["infoblox rpz"],
        column_name="Response Policy Zone",
    )
    network_view: str | None = Param(
        description="Network view",
        default=DEFAULT_NETWORK_VIEW,
        primary=True,
        cef_types=["infoblox view"],
        column_name="Network View",
    )


class BlockIpParams(IpRpzParams):
    ip: str = Param(
        description="IP/CIDR to block",
        required=True,
        primary=True,
        cef_types=["ip"],
        column_name="IP",
    )
    comment: str | None = Param(description="Comment (maximum 256 characters)", required=False)


class BlockIpOutput(ActionOutput):
    reference_link: str | None = OutputField(
        example_values=["record:rpz:cname:ipaddress/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:10.0.0.5.test_zone/default"]
    )


class DomainRpzParams(Params):
    domain: str = Param(
        description="Domain to unblock",
        required=True,
        primary=True,
        cef_types=["domain", "url"],
        column_name="Domain",
    )
    rp_zone: str = Param(
        description="FQDN of response policy zone",
        required=True,
        primary=True,
        cef_types=["infoblox rpz"],
        column_name="Response Policy Zone",
    )
    network_view: str | None = Param(
        description="Network view",
        default=DEFAULT_NETWORK_VIEW,
        primary=True,
        cef_types=["infoblox view"],
        column_name="Network View",
    )


class BlockDomainParams(DomainRpzParams):
    domain: str = Param(
        description="Domain to block",
        required=True,
        primary=True,
        cef_types=["domain", "url"],
        column_name="Domain",
    )
    rp_zone: str = Param(
        description="FQDN of response policy zone",
        required=True,
        primary=True,
        cef_types=["infoblox rpz"],
        column_name="RP Zone",
    )
    comment: str | None = Param(description="Comment (maximum 256 characters)", required=False)


class DomainOutput(ActionOutput):
    reference_link: str | None = OutputField(
        example_values=["record:rpz:cname/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:www.test.abc.test_zone/default"]
    )


class ListRpzParams(Params):
    network_view: str | None = Param(
        description="Network view",
        default=DEFAULT_NETWORK_VIEW,
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


class DiscoveredDataOutput(ActionOutput):
    first_discovered: float | None = OutputField(example_values=[1495071666])
    last_discovered: float | None = OutputField(example_values=[1495071666])
    mac_address: str | None = OutputField(cef_types=["mac address"], example_values=["0a:10:10:a0:a0:10"])
    os: str | None = OutputField(example_values=["Linux"])


class ListHostsOutput(ActionOutput):
    ip: str | None = OutputField(cef_types=["ip"], example_values=["10.0.0.5"], column_name="IP")
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
