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
"""Register Infoblox actions with the SOAR SDK application."""

from soar_sdk.action_results import ActionOutput
from soar_sdk.app import App

from .block_domain import (
    BlockDomainParams,
    DomainOutput as BlockDomainOutput,
    apply_table_column_metadata as apply_block_domain_column_metadata,
    block_domain,
)
from .block_ip import (
    BlockIpOutput,
    BlockIpParams,
    apply_table_column_metadata as apply_block_ip_column_metadata,
    block_ip,
)
from .get_network_info import GetNetworkInfoOutput, GetNetworkInfoParams, GetNetworkInfoSummary, get_network_info
from .get_system_info import GetSystemInfoOutput, GetSystemInfoParams, GetSystemInfoSummary, apply_table_column_order, get_system_info
from .list_hosts import ListHostsOutput, ListHostsParams, ListHostsSummary, list_hosts
from .list_network_view import ListNetworkViewOutput, ListNetworkViewParams, ListNetworkViewSummary, list_network_view
from .list_rpz import ListRpzOutput, ListRpzParams, ListRpzSummary, list_rpz
from .make_request import make_request
from .unblock_domain import (
    DomainOutput as UnblockDomainOutput,
    DomainRpzParams,
    apply_table_column_metadata as apply_unblock_domain_column_metadata,
    unblock_domain,
)
from .unblock_ip import (
    BlockIpOutput as UnblockIpOutput,
    IpRpzParams,
    apply_table_column_metadata as apply_unblock_ip_column_metadata,
    unblock_ip,
)


def register_actions(app: App) -> App:
    """Register legacy playbook actions and the SDK make_request action."""
    app.register_action(
        list_network_view,
        name="list network view",
        identifier="list_network_view",
        description="List available network views",
        action_type="investigate",
        read_only=True,
        params_class=ListNetworkViewParams,
        output_class=ListNetworkViewOutput,
        summary_type=ListNetworkViewSummary,
        render_as="table",
    )
    app.register_action(
        get_network_info,
        name="get network info",
        identifier="get_network_info",
        description="List available networks",
        verbose="Get network information for an IP or IP range (in CIDR notation). If an IP is not provided, return all network ranges.",
        action_type="investigate",
        read_only=True,
        params_class=GetNetworkInfoParams,
        output_class=GetNetworkInfoOutput,
        summary_type=GetNetworkInfoSummary,
        render_as="table",
    )
    get_system_info_action = app.register_action(
        get_system_info,
        name="get system info",
        identifier="get_system_info",
        description="Get the leases for the given IP/domain",
        verbose="Default value for <b>network_view</b> is 'default'. This action will not fetch system information of a host that has static IP and belongs to a non-default network view.",
        action_type="investigate",
        read_only=True,
        params_class=GetSystemInfoParams,
        output_class=GetSystemInfoOutput,
        summary_type=GetSystemInfoSummary,
        render_as="table",
    )
    apply_table_column_order(get_system_info_action)
    block_ip_action = app.register_action(
        block_ip,
        name="block ip",
        identifier="block_ip",
        description="Block an IP",
        verbose="This action blocks the IP by creating an appropriate RPZ. It blocks the domain by modifying the response of the DNS recursive query. The domain will not resolve the IP address/network. If all the IP addresses of the domain are blocked, the domain will be blocked. Each RPZ can have various rules associated with it. The response of a recursive query is modified if it matches any of the RPZ rules. The responses are first matched with the RPZ rules, and if there is a match, the rule defined at the RPZ level override is used. The override depends on the order of RPZ. The RPZs are prioritized in ascending order. Ensure that the specified RPZ has policy override 'None(GIVEN)', so that rule defined at RPZ level override is used. This action uses a multistep approach to block the IP:<ul><li>Check if RPZ exists with policy override 'None(GIVEN)'. If not, action will fail.</li><li>Add the RPZ rule 'Block IP Address (No Such Domain)' with the specified IP address. If another RPZ rule with a specified IP already exists with other than (No Such Domain) policy, the action will fail.</li></ul>Default value for <b>network_view</b> is 'default'.",
        action_type="contain",
        read_only=False,
        params_class=BlockIpParams,
        output_class=BlockIpOutput,
        summary_type=ActionOutput,
        render_as="table",
    )
    apply_block_ip_column_metadata(block_ip_action)
    unblock_ip_action = app.register_action(
        unblock_ip,
        name="unblock ip",
        identifier="unblock_ip",
        description="Unblock an IP",
        verbose="This action uses a multistep approach to unblock the IP:<ul><li>Check if RPZ exists with policy override 'None(GIVEN)'. If not, action will fail.</li><li>Remove the RPZ rule 'Block IP Address (No Such Domain)' with the specified IP address.</ul>Default value for <b>network_view</b> is 'default'.",
        action_type="correct",
        read_only=False,
        params_class=IpRpzParams,
        output_class=UnblockIpOutput,
        summary_type=ActionOutput,
        render_as="table",
    )
    apply_unblock_ip_column_metadata(unblock_ip_action)
    block_domain_action = app.register_action(
        block_domain,
        name="block domain",
        identifier="block_domain",
        description="Block a domain",
        verbose="This action blocks the domain by creating appropriate RPZ. Each RPZ can have various rules associated with it. The response of a recursive query is modified if it matches any of the RPZ rules. The responses are first matched with the RPZ rules, and if there is a match, the rule defined at the RPZ level override is used. The override depends on the order of RPZ. The RPZs are prioritized in ascending order. Ensure that the specified RPZ has policy override 'None(GIVEN)', so that rule defined at RPZ level override is used. This action uses a multistep approach to block the domain:<ul><li>Check if RPZ exists with policy override 'None(GIVEN)'. If not, action will fail.</li><li>Add the RPZ rule 'Block Domain Name (No Such Domain)' with the specified domain. If another RPZ rule with a specified domain already exists with other than (No Such Domain) policy, the action will fail.</li></ul>Default value for <b>network_view</b> is 'default'.",
        action_type="contain",
        read_only=False,
        params_class=BlockDomainParams,
        output_class=BlockDomainOutput,
        summary_type=ActionOutput,
        render_as="table",
    )
    apply_block_domain_column_metadata(block_domain_action)
    unblock_domain_action = app.register_action(
        unblock_domain,
        name="unblock domain",
        identifier="unblock_domain",
        description="Unblock a domain",
        verbose="This action uses a multistep approach to unblock the domain:<ul><li>Check if RPZ exists with policy override 'None(GIVEN)'. If not, action will fail.</li><li>Remove the RPZ rule 'Block Domain Name (No Such Domain)' with the specified domain.</ul>Default value for <b>network_view</b> is 'default'.",
        action_type="correct",
        read_only=False,
        params_class=DomainRpzParams,
        output_class=UnblockDomainOutput,
        summary_type=ActionOutput,
        render_as="table",
    )
    apply_unblock_domain_column_metadata(unblock_domain_action)
    app.register_action(
        list_rpz,
        name="list rpz",
        identifier="list_rpz",
        description="List details of Response Policy Zones",
        verbose="Default value for <b>network_view</b> is 'default'.",
        action_type="investigate",
        read_only=True,
        params_class=ListRpzParams,
        output_class=ListRpzOutput,
        summary_type=ListRpzSummary,
        render_as="table",
    )
    app.register_action(
        list_hosts,
        name="list hosts",
        identifier="list_hosts",
        description="List available hosts",
        action_type="investigate",
        read_only=True,
        params_class=ListHostsParams,
        output_class=ListHostsOutput,
        summary_type=ListHostsSummary,
        render_as="table",
    )
    app.make_request()(make_request)
    return app


__all__ = ["register_actions"]
