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
"""Explicit SDK action contracts, independent of application model definitions."""

import importlib
from typing import get_args

import pytest


sdk = importlib.import_module("src.app")

# Parameter tuples: data type, required flag, default, description.
# Output tuples: data type, CEF types, examples, column name, column order.
# These fixed expectations must not be derived from the app under test.
ACTION_CONTRACTS = {
    "list_network_view": {
        "name": "list network view",
        "type": "investigate",
        "read_only": True,
        "description": "List available network views",
        "verbose": "",
        "parameters": {},
        "output": {
            "action_result.data.*._ref": ("string", [], ["networkview/AA1aAa1aaAaa1Aa1aAa:default/true"], None, None),
            "action_result.data.*.comment": ("string", [], ["Test comment"], None, None),
            "action_result.data.*.is_default": ("boolean", [], [True, False], "Default", 1),
            "action_result.data.*.name": ("string", ["infoblox view"], ["default"], "Network View", 0),
            "action_result.summary.total_network_view": ("numeric", [], [2], None, None),
        },
    },
    "get_network_info": {
        "name": "get network info",
        "type": "investigate",
        "read_only": True,
        "description": "List available networks",
        "verbose": "Get network information for an IP or IP range (in CIDR notation). If an IP is not provided, return all network ranges.",
        "parameters": {
            "ip": ("string", False, None, "IP or IP network (CIDR notation)"),
            "network_view": ("string", False, None, "Network view"),
        },
        "output": {
            "action_result.parameter.ip": ("string", ["ip", "ipv6", "cidr"], None, None, None),
            "action_result.parameter.network_view": ("string", ["infoblox view"], None, None, None),
            "action_result.data.*._ref": (
                "string",
                [],
                ["range/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:10.0.0.1/10.254.254.254/Internal%20Networks"],
                None,
                None,
            ),
            "action_result.data.*.comment": ("string", [], ["Example of a comment"], "Comment", 2),
            "action_result.data.*.network": ("string", ["ip", "ipv6", "cidr"], ["10.0.0.0/8"], "Network", 0),
            "action_result.data.*.network_view": ("string", ["infoblox view"], ["Internal Networks"], "Network View", 1),
            "action_result.summary.number_of_matching_networks": ("numeric", [], [1], None, None),
        },
    },
    "get_system_info": {
        "name": "get system info",
        "type": "investigate",
        "read_only": True,
        "description": "Get the leases for the given IP/domain",
        "verbose": "Default value for <b>network_view</b> is 'default'. This action will not fetch system "
        "information of a host that has static IP and belongs to a non-default network view.",
        "parameters": {"ip_hostname": ("string", True, None, "IP/Hostname"), "network_view": ("string", False, "default", "Network view")},
        "output": {
            "action_result.parameter.ip_hostname": ("string", ["ip", "ipv6", "host name"], None, None, None),
            "action_result.parameter.network_view": ("string", ["infoblox view"], None, "Network View", 9),
            "action_result.data.*._ref": ("string", [], ["lease/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:10.0.0.5/default"], None, None),
            "action_result.data.*.address": ("string", ["ip", "ipv6"], ["10.0.0.5"], "Host IP", 0),
            "action_result.data.*.billing_class": ("string", [], None, None, None),
            "action_result.data.*.binding_state": ("string", [], ["FREE"], "Binding State", 4),
            "action_result.data.*.client_hostname": ("string", ["host name"], None, "Client Host Name", 1),
            "action_result.data.*.cltt": ("string", [], ["2010-10-10 10:11:12"], "Client Last Transaction Time", 7),
            "action_result.data.*.ends": ("string", [], ["2010-10-10 12:11:12"], "Ends", 6),
            "action_result.data.*.hardware": ("string", ["mac address"], ["0a:10:10:a0:a0:10"], None, None),
            "action_result.data.*.ipv6_duid": ("string", [], None, None, None),
            "action_result.data.*.ipv6_iaid": ("string", [], None, None, None),
            "action_result.data.*.ipv6_preferred_lifetime": ("numeric", [], [604800], None, None),
            "action_result.data.*.ipv6_prefix_bits": ("numeric", [], [48], None, None),
            "action_result.data.*.is_invalid_mac": ("boolean", [], [True, False], None, None),
            "action_result.data.*.network": ("string", [], None, "Network", 8),
            "action_result.data.*.network_view": ("string", ["infoblox view"], ["default"], None, None),
            "action_result.data.*.never_ends": ("boolean", [], [True, False], None, None),
            "action_result.data.*.never_starts": ("boolean", [], [True, False], None, None),
            "action_result.data.*.next_binding_state": ("string", [], ["ACTIVE"], None, None),
            "action_result.data.*.on_commit": ("string", [], None, None, None),
            "action_result.data.*.on_expiry": ("string", [], None, None, None),
            "action_result.data.*.on_release": ("string", [], None, None, None),
            "action_result.data.*.option": ("string", [], None, None, None),
            "action_result.data.*.os": ("string", [], ["Linux"], "OS", 3),
            "action_result.data.*.protocol": ("string", [], ["IPV4"], None, None),
            "action_result.data.*.remote_id": ("string", [], None, None, None),
            "action_result.data.*.served_by": ("string", ["ip", "ipv6"], ["10.0.0.7"], "Served By", 10),
            "action_result.data.*.server_host_name": ("string", ["host name"], ["test-01.lab.test.local"], "Server Host Name", 2),
            "action_result.data.*.starts": ("string", [], ["2010-10-10 10:11:12"], "Starts", 5),
            "action_result.data.*.tsfp": ("string", [], ["1504274705"], None, None),
            "action_result.data.*.tstp": ("string", [], ["1504274905"], None, None),
            "action_result.data.*.uid": ("string", [], None, None, None),
            "action_result.data.*.username": ("string", [], None, None, None),
            "action_result.data.*.variable": ("string", [], ['lt="undefined"'], None, None),
            "action_result.summary.binding_state": ("string", [], None, None, None),
            "action_result.summary.is_static_ip": ("boolean", [], [True, False], None, None),
            "action_result.summary.mac_address": ("string", ["mac address"], ["0a:10:10:a0:a0:10"], None, None),
            "action_result.summary.never_ends": ("boolean", [], [True, False], None, None),
        },
    },
    "unblock_ip": {
        "name": "unblock ip",
        "type": "correct",
        "read_only": False,
        "description": "Unblock an IP",
        "verbose": "This action uses a multistep approach to unblock the IP:<ul><li>Check if RPZ exists with "
        "policy override 'None(GIVEN)'. If not, action will fail.</li><li>Remove the RPZ rule "
        "'Block IP Address (No Such Domain)' with the specified IP address.</ul>Default value for "
        "<b>network_view</b> is 'default'.",
        "parameters": {
            "ip": ("string", True, None, "IP/CIDR to unblock"),
            "rp_zone": ("string", True, None, "FQDN of response policy zone"),
            "network_view": ("string", False, "default", "Network view"),
        },
        "output": {
            "action_result.parameter.ip": ("string", ["ip", "ipv6", "cidr"], None, "IP", 0),
            "action_result.parameter.network_view": ("string", ["infoblox view"], None, "Network View", 2),
            "action_result.parameter.rp_zone": ("string", ["infoblox rpz"], None, "Response Policy Zone", 1),
            "action_result.data.*.reference_link": (
                "string",
                [],
                ["record:rpz:cname:ipaddress/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:10.0.0.5.test_zone/default"],
                None,
                None,
            ),
        },
    },
    "block_ip": {
        "name": "block ip",
        "type": "contain",
        "read_only": False,
        "description": "Block an IP",
        "verbose": "This action blocks the IP by creating an appropriate RPZ. It blocks the domain by modifying "
        "the response of the DNS recursive query. The domain will not resolve the IP address/network. "
        "If all the IP addresses of the domain are blocked, the domain will be blocked. Each RPZ can "
        "have various rules associated with it. The response of a recursive query is modified if it "
        "matches any of the RPZ rules. The responses are first matched with the RPZ rules, and if "
        "there is a match, the rule defined at the RPZ level override is used. The override depends "
        "on the order of RPZ. The RPZs are prioritized in ascending order. Ensure that the specified "
        "RPZ has policy override 'None(GIVEN)', so that rule defined at RPZ level override is used. "
        "This action uses a multistep approach to block the IP:<ul><li>Check if RPZ exists with "
        "policy override 'None(GIVEN)'. If not, action will fail.</li><li>Add the RPZ rule 'Block IP "
        "Address (No Such Domain)' with the specified IP address. If another RPZ rule with a "
        "specified IP already exists with other than (No Such Domain) policy, the action will "
        "fail.</li></ul>Default value for <b>network_view</b> is 'default'.",
        "parameters": {
            "ip": ("string", True, None, "IP/CIDR to block"),
            "rp_zone": ("string", True, None, "FQDN of response policy zone"),
            "network_view": ("string", False, "default", "Network view"),
            "comment": ("string", False, None, "Comment (maximum 256 characters)"),
        },
        "output": {
            "action_result.parameter.comment": ("string", [], None, None, None),
            "action_result.parameter.ip": ("string", ["ip", "ipv6", "cidr"], None, "IP", 0),
            "action_result.parameter.network_view": ("string", ["infoblox view"], None, "Network View", 2),
            "action_result.parameter.rp_zone": ("string", ["infoblox rpz"], None, "Response Policy Zone", 1),
            "action_result.data.*.reference_link": (
                "string",
                [],
                ["record:rpz:cname:ipaddress/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:10.0.0.5.test_zone/default"],
                None,
                None,
            ),
        },
    },
    "unblock_domain": {
        "name": "unblock domain",
        "type": "correct",
        "read_only": False,
        "description": "Unblock a domain",
        "verbose": "This action uses a multistep approach to unblock the domain:<ul><li>Check if RPZ "
        "exists with policy override 'None(GIVEN)'. If not, action will fail.</li><li>Remove "
        "the RPZ rule 'Block Domain Name (No Such Domain)' with the specified "
        "domain.</ul>Default value for <b>network_view</b> is 'default'.",
        "parameters": {
            "domain": ("string", True, None, "Domain to unblock"),
            "rp_zone": ("string", True, None, "FQDN of response policy zone"),
            "network_view": ("string", False, "default", "Network view"),
        },
        "output": {
            "action_result.parameter.domain": ("string", ["domain", "url"], None, "Domain", 0),
            "action_result.parameter.network_view": ("string", ["infoblox view"], None, "Network View", 2),
            "action_result.parameter.rp_zone": ("string", ["infoblox rpz"], None, "Response Policy Zone", 1),
            "action_result.data.*.reference_link": (
                "string",
                [],
                ["record:rpz:cname/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:www.test.abc.test_zone/default"],
                None,
                None,
            ),
        },
    },
    "block_domain": {
        "name": "block domain",
        "type": "contain",
        "read_only": False,
        "description": "Block a domain",
        "verbose": "This action blocks the domain by creating appropriate RPZ. Each RPZ can have various "
        "rules associated with it. The response of a recursive query is modified if it matches "
        "any of the RPZ rules. The responses are first matched with the RPZ rules, and if there "
        "is a match, the rule defined at the RPZ level override is used. The override depends on "
        "the order of RPZ. The RPZs are prioritized in ascending order. Ensure that the specified "
        "RPZ has policy override 'None(GIVEN)', so that rule defined at RPZ level override is "
        "used. This action uses a multistep approach to block the domain:<ul><li>Check if RPZ "
        "exists with policy override 'None(GIVEN)'. If not, action will fail.</li><li>Add the RPZ "
        "rule 'Block Domain Name (No Such Domain)' with the specified domain. If another RPZ rule "
        "with a specified domain already exists with other than (No Such Domain) policy, the "
        "action will fail.</li></ul>Default value for <b>network_view</b> is 'default'.",
        "parameters": {
            "domain": ("string", True, None, "Domain to block"),
            "rp_zone": ("string", True, None, "FQDN of response policy zone"),
            "network_view": ("string", False, "default", "Network view"),
            "comment": ("string", False, None, "Comment (maximum 256 characters)"),
        },
        "output": {
            "action_result.parameter.comment": ("string", [], None, None, None),
            "action_result.parameter.domain": ("string", ["domain", "url"], None, "Domain", 0),
            "action_result.parameter.network_view": ("string", ["infoblox view"], None, "Network View", 2),
            "action_result.parameter.rp_zone": ("string", ["infoblox rpz"], None, "RP Zone", 1),
            "action_result.data.*.reference_link": (
                "string",
                [],
                ["record:rpz:cname/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:www.test.abc.test_zone/default"],
                None,
                None,
            ),
        },
    },
    "list_rpz": {
        "name": "list rpz",
        "type": "investigate",
        "read_only": True,
        "description": "List details of Response Policy Zones",
        "verbose": "Default value for <b>network_view</b> is 'default'.",
        "parameters": {"network_view": ("string", False, "default", "Network view")},
        "output": {
            "action_result.parameter.network_view": ("string", ["infoblox view"], None, None, None),
            "action_result.data.*._ref": ("string", [], ["zone_rp/AA1aAa1aaAaa1Aa1aAa:test/default"], None, None),
            "action_result.data.*.comment": ("string", [], ["Test comment"], "Comment", 7),
            "action_result.data.*.disable": ("boolean", [], [True, False], None, None),
            "action_result.data.*.fqdn": ("string", ["infoblox rpz"], ["test_fqdn"], "FQDN Of RPZ", 0),
            "action_result.data.*.network_view": ("string", ["infoblox view"], ["default"], "Network View", 3),
            "action_result.data.*.ns_group": ("string", [], ["PRIMARY"], None, None),
            "action_result.data.*.primary_type": ("string", [], ["Grid"], None, None),
            "action_result.data.*.rpz_last_updated_time": ("string", [], None, "Last Updated", 6),
            "action_result.data.*.rpz_policy": ("string", [], ["GIVEN"], "RPZ Policy Override", 2),
            "action_result.data.*.rpz_priority": ("numeric", [], [1], "Priority", 5),
            "action_result.data.*.rpz_severity": ("string", [], ["MAJOR"], "Severity", 4),
            "action_result.data.*.rpz_type": ("string", [], ["LOCAL"], "Type", 1),
            "action_result.data.*.substitute_name": ("string", [], ["test_name"], None, None),
            "action_result.summary.total_response_policy_zones": ("numeric", [], [3], None, None),
        },
    },
    "list_hosts": {
        "name": "list hosts",
        "type": "investigate",
        "read_only": True,
        "description": "List available hosts",
        "verbose": "",
        "parameters": {},
        "output": {
            "action_result.data.*._ref": (
                "string",
                [],
                ["record:a/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:test_nv_a_record.test_zone/default.dns"],
                None,
                None,
            ),
            "action_result.data.*.discovered_data.first_discovered": ("numeric", [], [1495071666], None, None),
            "action_result.data.*.discovered_data.last_discovered": ("numeric", [], [1495071666], None, None),
            "action_result.data.*.discovered_data.mac_address": ("string", ["mac address"], ["0a:10:10:a0:a0:10"], None, None),
            "action_result.data.*.discovered_data.os": ("string", [], ["Linux"], None, None),
            "action_result.data.*.ip": ("string", ["ip", "ipv6"], ["10.0.0.5"], "IP", 0),
            "action_result.data.*.name": ("string", ["host name"], ["test"], "Host Name", 1),
            "action_result.data.*.view": ("string", ["infoblox view"], ["External DNS"], "Network View", 2),
            "action_result.data.*.zone": ("string", [], ["example.com"], "DNS Zone", 3),
            "action_result.summary.total_hosts": ("numeric", [], [1122], None, None),
        },
    },
}

COMMON_OUTPUT_CONTRACTS = {
    "action_result.status": ("string", [], None, None, None),
    "action_result.message": ("string", [], None, None, None),
    "summary.total_objects": ("numeric", [], [1], None, None),
    "summary.total_objects_successful": ("numeric", [], [1], None, None),
}


def test_imported_application_registers_expected_actions_and_connectivity_hook():
    actions = sdk.app.get_actions()
    assert sdk.app.app_meta_info["name"] == "Infoblox DDI"
    assert sdk.app.app_meta_info["appid"] == "5ec38a6e-18c3-4cc3-ab47-2754b56aea50"
    assert set(actions) == set(ACTION_CONTRACTS) | {"make_request", "test_connectivity"}
    assert actions["test_connectivity"].meta.type == "test"
    assert actions["test_connectivity"].meta.read_only is True


@pytest.mark.parametrize("identifier", ACTION_CONTRACTS)
def test_action_parameters_and_output_schema_match_contract(identifier):
    expected = ACTION_CONTRACTS[identifier]
    action = sdk.app.get_actions()[identifier]
    assert action.meta.action == expected["name"]
    assert action.meta.type == expected["type"]
    assert action.meta.read_only is expected["read_only"]
    assert action.meta.description == expected["description"]
    assert action.meta.verbose == expected["verbose"]

    parameters = action.meta.parameters.model_fields
    assert list(parameters) == list(expected["parameters"])
    for name, (data_type, required, default, description) in expected["parameters"].items():
        field = parameters[name]
        annotation = next(
            (arg for arg in get_args(field.annotation) if arg is not type(None)),
            field.annotation,
        )
        assert {str: "string", int: "numeric", float: "numeric", bool: "boolean"}.get(annotation) == data_type, name
        assert field.is_required() is required, name
        assert field.description == description, name
        if not required or default is not None:
            assert field.default == default, name

    output = {item["data_path"]: item for item in action.meta.model_dump()["output"]}
    expected_output = {**COMMON_OUTPUT_CONTRACTS, **expected["output"]}
    assert set(output) == set(expected_output)
    for path, (data_type, contains, examples, column_name, column_order) in expected_output.items():
        field = output[path]
        assert field["data_type"] == data_type, path
        assert field.get("contains", []) == contains, path
        # Status/message examples are SDK-owned; parameter examples are not
        # configurable in the parameter models. Preserve the other contracts.
        if path in {"action_result.status", "action_result.message"}:
            continue
        if not path.startswith("action_result.parameter."):
            assert field.get("example_values") == examples, path
        assert field.get("column_name") == column_name, path
        assert field.get("column_order") == column_order, path
