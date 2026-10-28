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
from __future__ import annotations

import importlib
import json
import time
from copy import deepcopy
from pathlib import Path
from typing import get_args, get_origin

import pytest
from soar_sdk.action_results import ActionResult
from soar_sdk.exceptions import ActionFailure

from src.actions import common as action_common
from src.actions.block_domain import BlockDomainParams
from src.actions.block_ip import BlockIpParams, block_ip
from src.actions.get_network_info import GetNetworkInfoParams, get_network_info
from src.actions.get_system_info import GetSystemInfoParams
from src.actions.list_hosts import ListHostsParams
from src.actions.list_network_view import ListNetworkViewParams
from src.actions.list_rpz import ListRpzParams
from src.actions.make_request import InfobloxMakeRequestParams
from src.actions.unblock_domain import UnblockDomainParams
from src.actions.unblock_ip import UnblockIpParams, unblock_ip
from src.asset import Asset
from src.consts import INFOBLOX_HOST_INFO_UNAVAILABLE, INFOBLOX_JSON_DATE_FORMAT
from src.infoblox_client import InfobloxApiError


sdk = importlib.import_module("src.app")
ROOT = Path(__file__).resolve().parents[1]


class FakeSoar:
    def __init__(self):
        self.message = None
        self.summary = None

    def set_message(self, message):
        self.message = message

    def set_summary(self, summary):
        self.summary = summary

    def get_message(self):
        return self.message or ""

    def get_summary(self):
        return self.summary


class FakeClient:
    def __init__(self, _asset):
        self.requests = []
        self.closed = False
        self.logout_called = False

    def paged_request(self, endpoint, **kwargs):
        self.requests.append(("paged", endpoint, kwargs))
        return []

    def wapi_request(self, endpoint, **kwargs):
        self.requests.append(("request", endpoint, kwargs))
        raise AssertionError("unexpected direct request")

    def rpz_details(self, *args, **kwargs):
        self.requests.append(("rpz", args, kwargs))
        return []

    def use_session_cookie(self):
        self.requests.append(("cookie",))

    def logout(self):
        self.logout_called = True

    def close(self):
        self.closed = True


class ApiResponse:
    def __init__(self, data):
        self.data = data


def make_asset(**overrides):
    values = {
        "url": "https://grid.example",
        "username": "api-user",
        "password": "pwd",  # pragma: allowlist secret
    }
    values.update(overrides)
    return Asset.model_validate(values)


def make_lease(**overrides):
    values = {
        "address": "192.0.2.1",
        "hardware": "00:11:22:33:44:55",
        "binding_state": "ACTIVE",
        "never_ends": False,
        "cltt": 1_700_000_000,
        "starts": 1_700_000_000,
        "ends": 1_700_000_100,
    }
    values.update(overrides)
    return values


@pytest.mark.parametrize("case", ["lease", "static_host", "network", "hosts_ipv4", "hosts_ipv6", "rpz"])
def test_later_row_error_preserves_completed_rows_and_summary(monkeypatch, case):
    client = FakeClient(None)
    expected_summary = {}
    if case == "lease":
        action_id = "get_system_info"
        params = GetSystemInfoParams(ip_hostname="192.0.2.1", network_view="other")
        good = make_lease()
        client.wapi_request = lambda endpoint, **kwargs: ApiResponse([deepcopy(good), make_lease(ends="bad timestamp")])
        expected_row = {
            **good,
            **{key: time.strftime(INFOBLOX_JSON_DATE_FORMAT, time.localtime(good[key])) for key in ("cltt", "starts", "ends")},
        }
        expected_summary = {"mac_address": good["hardware"], "binding_state": "ACTIVE", "never_ends": False, "is_static_ip": False}
        expected_data = [expected_row]
    elif case == "static_host":
        action_id = "get_system_info"
        params = GetSystemInfoParams(ip_hostname="static")
        good = {"name": "static.example", "zone": "example", "ipv4addr": "192.0.2.1", "discovered_data": {"os": "Linux"}}
        client.wapi_request = lambda endpoint, **kwargs: ApiResponse([] if endpoint == "/lease" else [good, {**good, "discovered_data": None}])
        expected_data = [{"client_hostname": "static", "hardware": None, "os": "Linux", "address": "192.0.2.1", "protocol": "IPV4"}]
        expected_summary = {"mac_address": None, "is_static_ip": True}
    elif case == "network":
        action_id = "get_network_info"
        params = GetNetworkInfoParams(ip="192.0.2.1")
        good = {"network": "192.0.2.0/24"}
        client.paged_request = lambda endpoint, **kwargs: [good, {"network": "bad network"}]
        expected_data = [good]
    elif case in {"hosts_ipv4", "hosts_ipv6"}:
        action_id = "list_hosts"
        params = ListHostsParams()
        good = {"ipv4addr": "192.0.2.1", "name": "host.example", "zone": "example"}
        good_ipv6 = {"ipv6addr": "2001:db8::1", "name": "v6.example", "zone": "example"}

        def paged(endpoint, **kwargs):
            if endpoint == "/record:a":
                return [good, {}] if case == "hosts_ipv4" else [good]
            return [good_ipv6, {}]

        client.paged_request = paged
        expected_data = [{"ip": "192.0.2.1", "name": "host", "zone": "example"}]
        if case == "hosts_ipv6":
            expected_data.append({"ip": "2001:db8::1", "name": "v6", "zone": "example"})
    else:
        action_id = "list_rpz"
        params = ListRpzParams()
        timestamp = 1_700_000_000
        client.rpz_details = lambda *args, **kwargs: [
            {"fqdn": "good.example", "rpz_last_updated_time": timestamp},
            {"fqdn": "bad.example", "rpz_last_updated_time": "bad timestamp"},
        ]
        expected_data = [{"fqdn": "good.example", "rpz_last_updated_time": time.strftime(INFOBLOX_JSON_DATE_FORMAT, time.localtime(timestamp))}]
        expected_summary = {"total_response_policy_zones": 2}

    monkeypatch.setattr(action_common, "InfobloxClient", lambda asset: client)
    soar = FakeSoar()
    before = len(sdk.app.actions_manager.get_results())
    assert sdk.app.actions_manager.get_action(action_id)(params, soar=soar, asset=make_asset()) is False
    result = sdk.app.actions_manager.get_results()[before]
    assert result.get_data() == expected_data
    assert result.get_summary() == expected_summary
    assert soar.get_summary().model_dump(exclude_unset=True) == expected_summary
    assert result.get_message().startswith("Exception occurred. Error message:")
    assert client.logout_called and client.closed


@pytest.mark.parametrize(
    ("address", "address_key", "other_address", "endpoint"),
    [
        ("192.0.2.1", "ipv4addr", "192.0.2.99", "/record:a"),
        ("2001:db8::1", "ipv6addr", "2001:db8::99", "/record:aaaa"),
    ],
)
def test_lease_enrichment_accepts_single_address_family_records(monkeypatch, address, address_key, other_address, endpoint):
    client = FakeClient(None)

    def request(path, **kwargs):
        client.requests.append(path)
        if path == "/lease":
            return ApiResponse([make_lease(address=address)])
        return ApiResponse(
            [
                {address_key: other_address, "discovered_data": {"os": "Wrong host"}},
                {address_key: address, "discovered_data": {"os": "Linux"}},
            ]
        )

    client.wapi_request = request
    monkeypatch.setattr(action_common, "InfobloxClient", lambda asset: client)
    before = len(sdk.app.actions_manager.get_results())
    assert (
        sdk.app.actions_manager.get_action("get_system_info")(GetSystemInfoParams(ip_hostname=address), soar=FakeSoar(), asset=make_asset())
        is True
    )
    result = sdk.app.actions_manager.get_results()[before]
    assert result.get_data()[0]["os"] == "Linux"
    assert result.get_data()[0]["address"] == address
    assert result.get_summary()["is_static_ip"] is False
    assert client.requests == ["/lease", endpoint]


@pytest.mark.parametrize("business_failure", [False, True])
def test_logout_failure_does_not_rewrite_business_result(monkeypatch, business_failure):
    client = FakeClient(None)
    client.rpz_details = lambda *args, **kwargs: [{"rpz_policy": "GIVEN"}]
    logged_errors = []

    def request(endpoint, **kwargs):
        client.requests.append(kwargs["method"])
        if business_failure:
            raise InfobloxApiError("Business request failed")
        return ApiResponse("created-ref" if kwargs["method"] == "post" else [])

    def logout():
        client.logout_called = True
        raise InfobloxApiError("Logout failed")

    client.wapi_request = request
    client.logout = logout
    monkeypatch.setattr(action_common, "InfobloxClient", lambda asset: client)
    monkeypatch.setattr(action_common.logger, "error", lambda *args: logged_errors.append(args))
    soar = FakeSoar()
    before = len(sdk.app.actions_manager.get_results())
    assert (
        sdk.app.actions_manager.get_action("block_ip")(BlockIpParams(ip="192.0.2.1", rp_zone="block.example"), soar=soar, asset=make_asset())
        is not business_failure
    )
    result = sdk.app.actions_manager.get_results()[before]
    assert result.get_status() is not business_failure
    assert result.get_message() == ("Business request failed" if business_failure else "IP/CIDR blocked successfully")
    assert result.get_data() == ([] if business_failure else [{"reference_link": "created-ref"}])
    assert soar.get_message() == result.get_message()
    assert client.requests == ([("cookie",), "get"] if business_failure else [("cookie",), "get", "post"])
    assert logged_errors[0][0] == "Infoblox logout failed: %s"
    assert str(logged_errors[0][1]) == "Logout failed"
    assert client.logout_called and client.closed


def test_imported_application_registers_legacy_actions_and_sdk_connectivity_hook():
    actions = sdk.app.get_actions()
    legacy = json.loads((ROOT / "tests/fixtures/legacy-infoblox-manifest.json").read_text())
    expected = {action["identifier"] for action in legacy["actions"]}

    assert sdk.app.app_meta_info["name"] == legacy["name"]
    assert sdk.app.app_meta_info["appid"] == legacy["appid"]
    assert expected - {"test_asset_connectivity"} <= actions.keys()
    assert set(actions) == (expected - {"test_asset_connectivity"}) | {"make_request", "test_connectivity"}
    assert "test_asset_connectivity" not in actions
    assert "test_connectivity" in actions
    assert actions["test_connectivity"].meta.type == "test"
    assert actions["test_connectivity"].meta.read_only is True
    for legacy_action in legacy["actions"]:
        if legacy_action["identifier"] == "test_asset_connectivity":
            continue  # Replaced by the SDK's single app-level connectivity hook.
        action = actions[legacy_action["identifier"]]
        assert action.meta.action == legacy_action["action"]
        assert action.meta.type == legacy_action["type"]
        assert action.meta.read_only is legacy_action["read_only"]


def test_action_parameters_and_output_schema_match_legacy_contract():
    legacy = json.loads((ROOT / "tests/fixtures/legacy-infoblox-manifest.json").read_text())
    actions = sdk.app.get_actions()
    # These CEF mappings intentionally extend legacy metadata so Infoblox IP
    # actions can match IPv6 and CIDR values in playbooks as well as IPv4.
    cef_type_overrides = {
        ("block_ip", "action_result.parameter.ip"): ["ip", "ipv6", "cidr"],
        ("unblock_ip", "action_result.parameter.ip"): ["ip", "ipv6", "cidr"],
        ("get_network_info", "action_result.parameter.ip"): ["ip", "ipv6", "cidr"],
        ("get_network_info", "action_result.data.*.network"): ["ip", "ipv6", "cidr"],
        ("get_system_info", "action_result.parameter.ip_hostname"): ["ip", "ipv6", "host name"],
        ("get_system_info", "action_result.data.*.address"): ["ip", "ipv6"],
        ("get_system_info", "action_result.data.*.served_by"): ["ip", "ipv6"],
        ("list_hosts", "action_result.data.*.ip"): ["ip", "ipv6"],
    }
    for legacy_action in legacy["actions"]:
        if legacy_action["identifier"] == "test_asset_connectivity":
            continue  # The SDK app-level connectivity hook replaces this legacy action.
        action = actions[legacy_action["identifier"]]
        legacy_params = legacy_action.get("parameters", {})
        sdk_params = action.meta.parameters.model_fields

        assert list(sdk_params) == list(legacy_params)
        assert action.meta.description == legacy_action["description"]
        assert action.meta.verbose == legacy_action.get("verbose", "")
        for name, legacy_param in legacy_params.items():
            field = sdk_params[name]
            annotation = field.annotation
            if get_origin(annotation) is not None:
                annotation = next(
                    (arg for arg in get_args(annotation) if arg is not type(None)),
                    annotation,
                )
            data_type = {str: "string", int: "numeric", float: "numeric", bool: "boolean"}.get(annotation)
            assert data_type == legacy_param["data_type"], name
            assert field.is_required() is legacy_param.get("required", False), name
            assert field.description == legacy_param.get("description"), name
            if "default" in legacy_param:
                assert field.default == legacy_param["default"], name
            elif not legacy_param.get("required", False):
                assert field.default is None, name

        sdk_output = {item["data_path"]: item for item in action.meta.model_dump()["output"]}
        legacy_output = {item["data_path"]: item for item in legacy_action.get("output", [])}
        # The SDK does not serialize the legacy's empty string summary entry.
        if legacy_action["identifier"] in {"block_ip", "unblock_ip", "block_domain", "unblock_domain"}:
            legacy_output.pop("action_result.summary", None)
        assert set(sdk_output) == set(legacy_output)
        for path, legacy_field in legacy_output.items():
            sdk_field = sdk_output[path]
            assert sdk_field["data_type"] == legacy_field["data_type"], path
            expected_contains = cef_type_overrides.get(
                (legacy_action["identifier"], path),
                legacy_field.get("contains", []),
            )
            assert sdk_field.get("contains", []) == expected_contains, path
            # SDK-reserved status/message metadata and Param examples cannot be
            # configured in the action models; examples for action outputs are.
            if path not in {"action_result.status", "action_result.message"} and not path.startswith("action_result.parameter."):
                assert sdk_field.get("example_values") == legacy_field.get("example_values"), path
            if path in {"action_result.status", "action_result.message"}:
                continue
            if path.startswith("action_result.parameter."):
                assert sdk_field.get("column_name") == legacy_field.get("column_name"), path
                assert sdk_field.get("column_order") == legacy_field.get("column_order"), path
                continue
            assert sdk_field.get("column_name") == legacy_field.get("column_name"), path
            assert sdk_field.get("column_order") == legacy_field.get("column_order"), path


def test_registered_action_executes_and_preserves_raw_json_values(monkeypatch):
    client = FakeClient(None)
    row = {
        "_ref": "networkview/one",
        "name": "default",
        "is_default": False,
        "custom_object": {"count": 3, "active": True, "empty": None},
    }
    client.paged_request = lambda endpoint, **kwargs: client.requests.append(("paged", endpoint, kwargs)) or [row]
    monkeypatch.setattr(action_common, "InfobloxClient", lambda asset: client)
    soar = FakeSoar()
    action = sdk.app.actions_manager.get_action("list_network_view")

    before = len(sdk.app.actions_manager.get_results())
    assert action(ListNetworkViewParams(), soar=soar, asset=make_asset()) is True
    result = sdk.app.actions_manager.get_results()[before]

    assert isinstance(result, ActionResult)
    assert result.get_status() is True
    assert result.get_data() == [row]
    assert result.get_data()[0]["custom_object"] == {
        "count": 3,
        "active": True,
        "empty": None,
    }
    assert result.get_summary() == {"total_network_view": 1}
    assert soar.message == ""
    assert soar.summary.total_network_view == 1
    assert client.requests == [("paged", "/networkview", {"method": "get"})]
    assert client.logout_called and client.closed


def test_list_network_view_empty_response_matches_legacy_error(monkeypatch):
    client = FakeClient(None)
    monkeypatch.setattr(action_common, "InfobloxClient", lambda asset: client)
    soar = FakeSoar()

    before = len(sdk.app.actions_manager.get_results())
    assert sdk.app.actions_manager.get_action("list_network_view")(ListNetworkViewParams(), soar=soar, asset=make_asset()) is False
    result = sdk.app.actions_manager.get_results()[before]

    assert result.get_status() is False
    assert result.get_message() == "Network View information unavailable"
    assert result.get_data() == []


def test_get_network_info_filters_host_address_without_losing_structures(monkeypatch):
    client = FakeClient(None)

    def paged_request(endpoint, **kwargs):
        client.requests.append(("paged", endpoint, kwargs))
        return [
            {"network": "10.0.0.0/8", "network_view": "default", "leases": [1, 2]},
            {"network": "192.168.1.0/24", "network_view": "default", "enabled": False},
        ]

    client.paged_request = paged_request
    monkeypatch.setattr(action_common, "InfobloxClient", lambda asset: client)
    soar = FakeSoar()
    params = GetNetworkInfoParams(ip="10.1.2.3", network_view="default")

    before = len(sdk.app.actions_manager.get_results())
    assert sdk.app.actions_manager.get_action("get_network_info")(params, soar=soar, asset=make_asset()) is True
    result = sdk.app.actions_manager.get_results()[before]

    assert result.get_status() is True
    assert result.get_data() == [{"network": "10.0.0.0/8", "network_view": "default", "leases": [1, 2]}]
    assert result.get_summary() == {"number_of_matching_networks": 1}
    assert client.requests == [
        (
            "paged",
            "/network",
            {"params": {"network_view": "default"}, "method": "get"},
        )
    ]
    assert soar.message == ""

    client.paged_request = lambda endpoint, **kwargs: []
    empty_soar = FakeSoar()
    before = len(sdk.app.actions_manager.get_results())
    assert sdk.app.actions_manager.get_action("get_network_info")(GetNetworkInfoParams(), soar=empty_soar, asset=make_asset()) is True
    empty = sdk.app.actions_manager.get_results()[before]
    assert empty.get_data() == []
    assert empty.get_summary() == {"number_of_matching_networks": 0}
    assert empty.get_message() == ""

    cidr_client = FakeClient(None)
    monkeypatch.setattr(action_common, "InfobloxClient", lambda asset: cidr_client)
    cidr_soar = FakeSoar()
    before = len(sdk.app.actions_manager.get_results())
    assert (
        sdk.app.actions_manager.get_action("get_network_info")(
            GetNetworkInfoParams(ip="10.0.0.0/8", network_view="Internal"),
            soar=cidr_soar,
            asset=make_asset(),
        )
        is True
    )
    assert cidr_client.requests == [
        (
            "paged",
            "/network",
            {"params": {"network": "10.0.0.0/8", "network_view": "Internal"}, "method": "get"},
        )
    ]
    assert sdk.app.actions_manager.get_results()[before].get_summary() == {"number_of_matching_networks": 0}


@pytest.mark.parametrize(
    ("params_class", "required_values", "action"),
    [
        (GetNetworkInfoParams, {}, get_network_info),
        (UnblockIpParams, {"rp_zone": "block.example"}, unblock_ip),
        (BlockIpParams, {"rp_zone": "block.example"}, block_ip),
    ],
)
def test_ip_parameters_fail_before_client_creation(monkeypatch, params_class, required_values, action):
    for value in ("10.0.0.5", "2001:db8:abcd:12::", "1.1.1.0/28"):
        params_class.model_validate({**required_values, "ip": value})

    for value in ("not-an-ip", ""):
        params = params_class.model_validate({**required_values, "ip": value})
        monkeypatch.setattr(
            action_common,
            "InfobloxClient",
            lambda _asset: pytest.fail("invalid IP must fail before client creation"),
        )
        soar = FakeSoar()
        result = action(params, soar=soar, asset=make_asset())
        assert not result.get_status()
        assert result.get_message() == "parameter 'ip' validation failed"
        assert soar.get_message() == "parameter 'ip' validation failed"


def test_get_system_info_preserves_types_and_has_no_time_filter(monkeypatch):
    expected_times = {
        "cltt": 1_700_000_000,
        "starts": 1_700_000_000,
        "ends": 1_700_000_100,
    }
    lease = {
        "address": "10.0.0.5",
        "hardware": "00:11:22:33:44:55",
        "binding_state": "ACTIVE",
        "never_ends": False,
        **expected_times,
        "ipv6_prefix_bits": 64,
        "is_invalid_mac": False,
        "optional_value": None,
        "opaque": {"count": 2},
    }

    class SystemInfoClient(FakeClient):
        def wapi_request(self, endpoint, **kwargs):
            self.requests.append(("request", endpoint, kwargs))
            if endpoint == "/lease":
                return ApiResponse([lease])
            return ApiResponse([])

    client = SystemInfoClient(None)
    monkeypatch.setattr(action_common, "InfobloxClient", lambda asset: client)
    soar = FakeSoar()
    params = GetSystemInfoParams(ip_hostname="10.0.0.5")

    before = len(sdk.app.actions_manager.get_results())
    assert sdk.app.actions_manager.get_action("get_system_info")(params, soar=soar, asset=make_asset()) is True
    result = sdk.app.actions_manager.get_results()[before]

    data = result.get_data()[0]
    assert data["is_invalid_mac"] is False
    assert data["never_ends"] is False
    assert data["ipv6_prefix_bits"] == 64
    assert data["optional_value"] is None
    assert data["opaque"] == {"count": 2}
    for key, timestamp in expected_times.items():
        assert data[key] == time.strftime(INFOBLOX_JSON_DATE_FORMAT, time.localtime(timestamp))
    assert result.get_summary() == {
        "mac_address": "00:11:22:33:44:55",
        "binding_state": "ACTIVE",
        "never_ends": False,
        "is_static_ip": False,
    }
    lease_query = client.requests[0][2]["params"]
    assert lease_query["address"] == "10.0.0.5"
    assert "start_time" not in lease_query and "end_time" not in lease_query
    assert client.requests[1] == (
        "request",
        "/record:a",
        {
            "params": {
                "_return_fields": "ipv4addr,name,view,zone,discovered_data",
                "ipv4addr": "10.0.0.5",
                "view": "default",
            },
            "method": "get",
        },
    )
    assert soar.message == ""


@pytest.mark.parametrize(
    ("record_endpoint", "address_key", "address", "protocol"),
    [
        ("/record:a", "ipv4addr", "10.0.0.7", "IPV4"),
        ("/record:aaaa", "ipv6addr", "2001:db8::7", "IPV6"),
    ],
    ids=["a_record", "aaaa_only_hostname"],
)
def test_get_system_info_static_host_and_empty_result_messages(monkeypatch, record_endpoint, address_key, address, protocol):
    class StaticClient(FakeClient):
        def wapi_request(self, endpoint, **kwargs):
            self.requests.append(("request", endpoint, kwargs))
            if endpoint == "/lease":
                return ApiResponse([])
            if endpoint == record_endpoint:
                return ApiResponse(
                    [
                        {
                            address_key: address,
                            "name": "static.example.com",
                            "zone": "example.com",
                            "discovered_data": {
                                "mac_address": "aa:bb:cc:dd:ee:ff",
                                "os": "Linux",
                            },
                        }
                    ]
                )
            return ApiResponse([])

    client = StaticClient(None)
    monkeypatch.setattr(action_common, "InfobloxClient", lambda asset: client)
    soar = FakeSoar()
    params = GetSystemInfoParams(ip_hostname="static")

    before = len(sdk.app.actions_manager.get_results())
    assert sdk.app.actions_manager.get_action("get_system_info")(params, soar=soar, asset=make_asset()) is True
    result = sdk.app.actions_manager.get_results()[before]
    assert result.get_data() == [
        {
            "client_hostname": "static",
            "hardware": "aa:bb:cc:dd:ee:ff",
            "os": "Linux",
            "address": address,
            "protocol": protocol,
        }
    ]
    assert result.get_summary() == {
        "mac_address": "aa:bb:cc:dd:ee:ff",
        "is_static_ip": True,
    }
    assert result.get_message() == ""

    expected_endpoints = ["/lease", "/record:a"]
    if record_endpoint == "/record:aaaa":
        expected_endpoints.append("/record:aaaa")
    assert [request[1] for request in client.requests] == expected_endpoints
    assert client.requests[-1][2]["params"]["name~"] == "static"

    class EmptyClient(StaticClient):
        def wapi_request(self, endpoint, **kwargs):
            self.requests.append(("request", endpoint, kwargs))
            return ApiResponse([])

    empty_client = EmptyClient(None)
    monkeypatch.setattr(action_common, "InfobloxClient", lambda asset: empty_client)
    empty_soar = FakeSoar()
    before = len(sdk.app.actions_manager.get_results())
    assert sdk.app.actions_manager.get_action("get_system_info")(params, soar=empty_soar, asset=make_asset()) is True
    empty_result = sdk.app.actions_manager.get_results()[before]
    assert empty_result.get_data() == []
    assert empty_result.get_message() == INFOBLOX_HOST_INFO_UNAVAILABLE
    assert empty_result.get_summary() == {}


def test_get_system_info_preserves_explicitly_empty_network_view(monkeypatch):
    client = FakeClient(None)

    def request(endpoint, **kwargs):
        client.requests.append(("request", endpoint, kwargs))
        return ApiResponse([])

    client.wapi_request = request
    monkeypatch.setattr(action_common, "InfobloxClient", lambda asset: client)

    before = len(sdk.app.actions_manager.get_results())
    assert (
        sdk.app.actions_manager.get_action("get_system_info")(
            GetSystemInfoParams(ip_hostname="host.example", network_view=""),
            soar=FakeSoar(),
            asset=make_asset(),
        )
        is True
    )
    result = sdk.app.actions_manager.get_results()[before]
    assert result.get_message() == INFOBLOX_HOST_INFO_UNAVAILABLE
    assert client.requests == [
        (
            "request",
            "/lease",
            {
                "params": {
                    "_return_fields": (
                        "binding_state,starts,ends,address,billing_class,client_hostname,tsfp,tstp,uid,"
                        "remote_id,username,variable,cltt,hardware,network,network_view,option,protocol,"
                        "served_by,server_host_name,billing_class,ipv6_duid,ipv6_iaid,ipv6_preferred_lifetime,"
                        "ipv6_prefix_bits,is_invalid_mac,never_ends,never_starts,next_binding_state,on_commit,"
                        "on_expiry,on_release"
                    ),
                    "client_hostname": "host.example",
                    "network_view": "",
                },
                "method": "get",
            },
        )
    ]


def test_rpz_actions_preserve_explicitly_empty_network_view(monkeypatch):
    cases = [
        ("block_ip", BlockIpParams(ip="10.0.0.5", rp_zone="block.example", network_view="")),
        ("unblock_ip", UnblockIpParams(ip="10.0.0.5", rp_zone="block.example", network_view="")),
        (
            "block_domain",
            BlockDomainParams(domain="example.com", rp_zone="block.example", network_view=""),
        ),
        (
            "unblock_domain",
            UnblockDomainParams(domain="example.com", rp_zone="block.example", network_view=""),
        ),
    ]

    for action_id, params in cases:
        client = FakeClient(None)
        rpz_filters = []
        client.rpz_details = lambda filters, **kwargs: rpz_filters.append(filters) or [{"rpz_policy": "GIVEN"}]
        request_calls = []

        def request(endpoint, **kwargs):
            request_calls.append((endpoint, kwargs))
            return ApiResponse("created-ref" if kwargs.get("method") == "post" else [])

        client.wapi_request = request
        monkeypatch.setattr(action_common, "InfobloxClient", lambda asset: client)

        before = len(sdk.app.actions_manager.get_results())
        assert sdk.app.actions_manager.get_action(action_id)(params, soar=FakeSoar(), asset=make_asset()) is True
        result = sdk.app.actions_manager.get_results()[before]

        assert result.get_status() is True
        assert rpz_filters == [{"fqdn": "block.example", "view": ""}]
        assert request_calls[0][1]["params"]["view"] == ""
        if action_id in {"block_ip", "block_domain"}:
            assert request_calls[1][1].get("params", request_calls[1][1].get("data"))["view"] == ""


def test_block_domain_preserves_form_payload_and_nested_reference(monkeypatch):
    client = FakeClient(None)
    rpz_calls = []

    def rpz_details(*args, **kwargs):
        rpz_calls.append((args, kwargs))
        return [{"rpz_policy": "GIVEN"}]

    client.rpz_details = rpz_details
    calls = []

    def request(endpoint, **kwargs):
        calls.append((endpoint, kwargs))
        if "data" in kwargs:
            return ApiResponse({"_ref": "created", "details": {"id": 7}})
        return ApiResponse([])

    client.wapi_request = request
    monkeypatch.setattr(action_common, "InfobloxClient", lambda asset: client)
    soar = FakeSoar()
    params = BlockDomainParams(
        domain="https://münich.example/path",
        rp_zone="block.example",
        comment="case 7",
    )

    before = len(sdk.app.actions_manager.get_results())
    assert sdk.app.actions_manager.get_action("block_domain")(params, soar=soar, asset=make_asset()) is True
    result = sdk.app.actions_manager.get_results()[before]
    assert result.get_message() == "Domain blocked successfully"
    assert result.get_data() == [{"reference_link": {"_ref": "created", "details": {"id": 7}}}]
    assert rpz_calls == [(({"fqdn": "block.example", "view": "default"},), {"allow_not_found": False})]
    assert calls == [
        (
            "/record:rpz:cname",
            {
                "params": {
                    "name": "xn--mnich-kva.example.block.example",
                    "zone": "block.example",
                    "view": "default",
                },
                "method": "get",
            },
        ),
        (
            "/record:rpz:cname",
            {
                "data": {
                    "name": "xn--mnich-kva.example.block.example",
                    "rp_zone": "block.example",
                    "canonical": "",
                    "view": "default",
                    "comment": "case 7",
                }
            },
        ),
    ]


def test_unblock_ip_already_unblocked_message_and_api_error_message(monkeypatch):
    client = FakeClient(None)
    rpz_calls = []
    client.rpz_details = lambda *args, **kwargs: rpz_calls.append((args, kwargs)) or [{"rpz_policy": "GIVEN"}]
    requests = []
    client.wapi_request = lambda *args, **kwargs: requests.append((args, kwargs)) or ApiResponse([])
    monkeypatch.setattr(action_common, "InfobloxClient", lambda asset: client)
    soar = FakeSoar()
    params = UnblockIpParams(ip="10.0.0.5", rp_zone="block.example")

    before = len(sdk.app.actions_manager.get_results())
    assert sdk.app.actions_manager.get_action("unblock_ip")(params, soar=soar, asset=make_asset()) is True
    result = sdk.app.actions_manager.get_results()[before]
    assert result.get_message() == "IP/CIDR already unblocked"
    assert result.get_data() == []
    assert rpz_calls == [(({"fqdn": "block.example", "view": "default"},), {"allow_not_found": False})]
    assert requests == [
        (
            ("/record:rpz:cname:ipaddress",),
            {
                "params": {"name": "10.0.0.5.block.example", "zone": "block.example", "view": "default"},
                "method": "get",
            },
        )
    ]
    assert any(call[0] == "cookie" for call in client.requests)

    def failed_request(*args, **kwargs):
        raise InfobloxApiError("API failed\nStatus code: 503\nDetail: unavailable")

    client.paged_request = failed_request
    before = len(sdk.app.actions_manager.get_results())
    assert sdk.app.actions_manager.get_action("list_network_view")(ListNetworkViewParams(), soar=FakeSoar(), asset=make_asset()) is False
    failed = sdk.app.actions_manager.get_results()[before]
    assert failed.get_message() == "API failed\nStatus code: 503\nDetail: unavailable"


def test_sdk_test_connectivity_hook_invokes_the_asset_check(monkeypatch):
    client = FakeClient(None)
    client.wapi_request = lambda endpoint, **kwargs: client.requests.append(("request", endpoint, kwargs)) or ApiResponse({})
    monkeypatch.setattr(sdk, "InfobloxClient", lambda asset: client)
    monkeypatch.setattr(
        sdk.app,
        "_build_magic_args",
        lambda function, *, soar: {"soar": soar, "asset": make_asset()},
    )

    action = sdk.app.actions_manager.get_action("test_connectivity")
    assert action(soar=FakeSoar()) is True
    assert client.requests[0] == ("request", "/?_schema", {"method": "get", "timeout": 30})
    assert client.logout_called and client.closed


def test_sdk_test_connectivity_hook_reports_probe_failure(monkeypatch):
    client = FakeClient(None)
    client.wapi_request = lambda *args, **kwargs: (_ for _ in ()).throw(InfobloxApiError("unavailable"))
    monkeypatch.setattr(sdk, "InfobloxClient", lambda asset: client)
    monkeypatch.setattr(
        sdk.app,
        "_build_magic_args",
        lambda function, *, soar: {"soar": soar, "asset": make_asset()},
    )

    action = sdk.app.actions_manager.get_action("test_connectivity")
    assert action(soar=FakeSoar()) is False
    result = sdk.app.actions_manager.get_results()[-1]
    assert result.get_message().endswith("Connectivity test failed")
    assert client.logout_called and client.closed


@pytest.mark.parametrize("probe_failure", [False, True])
def test_connectivity_logout_failure_preserves_probe_result(monkeypatch, probe_failure):
    client = FakeClient(None)

    def request(*args, **kwargs):
        if probe_failure:
            raise InfobloxApiError("Probe failed")
        return ApiResponse({})

    def logout():
        client.logout_called = True
        raise InfobloxApiError("Logout failed")

    client.wapi_request = request
    client.logout = logout
    monkeypatch.setattr(sdk, "InfobloxClient", lambda asset: client)
    monkeypatch.setattr(sdk.app, "_build_magic_args", lambda function, *, soar: {"soar": soar, "asset": make_asset()})

    before = len(sdk.app.actions_manager.get_results())
    assert sdk.app.actions_manager.get_action("test_connectivity")(soar=FakeSoar()) is not probe_failure
    result = sdk.app.actions_manager.get_results()[before]
    expected_message = "Connectivity test failed" if probe_failure else "Test connectivity successful"
    assert result.get_message().endswith(expected_message)
    assert client.logout_called and client.closed


def test_block_ip_uses_legacy_query_payload_and_sets_summary_and_message(monkeypatch):
    client = FakeClient(None)
    client.rpz_details = lambda *args, **kwargs: [{"rpz_policy": "GIVEN"}]
    monkeypatch.setattr(action_common, "InfobloxClient", lambda asset: client)
    soar = FakeSoar()
    params = BlockIpParams(ip="10.0.0.5", rp_zone="block.example", comment="case 42")
    calls = []

    def request(endpoint, **kwargs):
        calls.append((endpoint, kwargs))
        if kwargs.get("method") == "post":
            return ApiResponse("created-ref")
        return ApiResponse([])

    client.wapi_request = request

    before = len(sdk.app.actions_manager.get_results())
    assert sdk.app.actions_manager.get_action("block_ip")(params, soar=soar, asset=make_asset()) is True
    result = sdk.app.actions_manager.get_results()[before]

    assert result.get_status() is True
    assert result.get_message() == "IP/CIDR blocked successfully"
    assert result.get_data() == [{"reference_link": "created-ref"}]
    assert calls == [
        (
            "/record:rpz:cname:ipaddress",
            {
                "params": {
                    "name": "10.0.0.5.block.example",
                    "zone": "block.example",
                    "view": "default",
                },
                "method": "get",
            },
        ),
        (
            "/record:rpz:cname:ipaddress",
            {
                "params": {
                    "name": "10.0.0.5.block.example",
                    "rp_zone": "block.example",
                    "canonical": "",
                    "view": "default",
                    "comment": "case 42",
                },
                "method": "post",
            },
        ),
    ]
    assert soar.message == "IP/CIDR blocked successfully"
    assert soar.summary.model_dump() == {}


def test_list_rpz_empty_and_not_found_paths_keep_legacy_messages(monkeypatch):
    client = FakeClient(None)
    rpz_calls = []

    def missing_rpz(*args, **kwargs):
        rpz_calls.append((args, kwargs))
        return {"resource_not_found": True, "error_message": None}

    client.rpz_details = missing_rpz
    monkeypatch.setattr(action_common, "InfobloxClient", lambda asset: client)
    soar = FakeSoar()

    before = len(sdk.app.actions_manager.get_results())
    assert sdk.app.actions_manager.get_action("list_rpz")(ListRpzParams(), soar=soar, asset=make_asset()) is False
    result = sdk.app.actions_manager.get_results()[before]

    assert result.get_status() is False
    assert result.get_message() is None
    assert rpz_calls == [(({"view": "default"},), {"allow_not_found": True})]

    client.rpz_details = lambda *args, **kwargs: {"resource_not_found": True}
    before = len(sdk.app.actions_manager.get_results())
    assert sdk.app.actions_manager.get_action("list_rpz")(ListRpzParams(), soar=FakeSoar(), asset=make_asset()) is False
    fallback = sdk.app.actions_manager.get_results()[before]
    assert fallback.get_message() == "This action gets the data from default network view only"

    timestamp = 1_700_000_000
    client.rpz_details = lambda *args, **kwargs: [{"fqdn": "block.example", "rpz_last_updated_time": timestamp}]
    before = len(sdk.app.actions_manager.get_results())
    assert sdk.app.actions_manager.get_action("list_rpz")(ListRpzParams(), soar=FakeSoar(), asset=make_asset()) is True
    timestamp_result = sdk.app.actions_manager.get_results()[before]
    assert timestamp_result.get_data() == [
        {
            "fqdn": "block.example",
            "rpz_last_updated_time": time.strftime(INFOBLOX_JSON_DATE_FORMAT, time.localtime(timestamp)),
        }
    ]
    assert timestamp_result.get_summary() == {"total_response_policy_zones": 1}

    client.rpz_details = lambda *args, **kwargs: []
    before = len(sdk.app.actions_manager.get_results())
    assert sdk.app.actions_manager.get_action("list_rpz")(ListRpzParams(), soar=FakeSoar(), asset=make_asset()) is True
    empty = sdk.app.actions_manager.get_results()[before]
    assert empty.get_data() == []
    assert empty.get_summary() == {"total_response_policy_zones": 0}
    assert empty.get_message() == ""

    views = []
    client.rpz_details = lambda filters, **kwargs: views.append(filters["view"]) or []
    assert (
        sdk.app.actions_manager.get_action("list_rpz")(
            ListRpzParams(network_view=""),
            soar=FakeSoar(),
            asset=make_asset(),
        )
        is True
    )
    assert views == [""]


def test_list_hosts_transforms_address_and_keeps_empty_success_message(monkeypatch):
    client = FakeClient(None)
    calls = []

    def paged(endpoint, **kwargs):
        calls.append((endpoint, kwargs))
        if endpoint == "/record:a":
            return [
                {
                    "ipv4addr": "10.0.0.5",
                    "name": "host.example.com",
                    "view": "default",
                    "zone": "example.com",
                }
            ]
        return []

    client.paged_request = paged
    monkeypatch.setattr(action_common, "InfobloxClient", lambda asset: client)
    soar = FakeSoar()

    before = len(sdk.app.actions_manager.get_results())
    assert sdk.app.actions_manager.get_action("list_hosts")(ListHostsParams(), soar=soar, asset=make_asset()) is True
    result = sdk.app.actions_manager.get_results()[before]

    assert result.get_data() == [
        {
            "name": "host",
            "view": "default",
            "zone": "example.com",
            "ip": "10.0.0.5",
        }
    ]
    assert result.get_summary() == {"total_hosts": 1}
    assert result.get_message() == ""
    assert soar.message == ""
    assert calls == [
        ("/record:a", {"params": {"_return_fields": "ipv4addr,name,view,zone"}, "method": "get"}),
        ("/record:aaaa", {"params": {"_return_fields": "ipv6addr,name,view,zone"}, "method": "get"}),
    ]

    client.paged_request = lambda endpoint, **kwargs: []
    before = len(sdk.app.actions_manager.get_results())
    assert sdk.app.actions_manager.get_action("list_hosts")(ListHostsParams(), soar=FakeSoar(), asset=make_asset()) is True
    empty = sdk.app.actions_manager.get_results()[before]
    assert empty.get_data() == []
    assert empty.get_summary() == {"total_hosts": 0}
    assert empty.get_message() == ""


def test_unblock_domain_already_unblocked_uses_legacy_message_and_cookie(monkeypatch):
    client = FakeClient(None)
    rpz_calls = []
    client.rpz_details = lambda *args, **kwargs: rpz_calls.append((args, kwargs)) or [{"rpz_policy": "GIVEN"}]
    requests = []
    client.wapi_request = lambda *args, **kwargs: requests.append((args, kwargs)) or ApiResponse([])
    monkeypatch.setattr(action_common, "InfobloxClient", lambda asset: client)
    params = UnblockDomainParams(domain="example.com", rp_zone="block.example")
    before = len(sdk.app.actions_manager.get_results())

    assert sdk.app.actions_manager.get_action("unblock_domain")(params, soar=FakeSoar(), asset=make_asset()) is True
    result = sdk.app.actions_manager.get_results()[before]
    assert result.get_message() == "Domain already unblocked"
    assert result.get_data() == []
    assert rpz_calls == [(({"fqdn": "block.example", "view": "default"},), {"allow_not_found": False})]
    assert requests == [
        (
            ("/record:rpz:cname",),
            {
                "params": {"name": "example.com.block.example", "zone": "block.example", "view": "default"},
                "method": "get",
            },
        )
    ]
    assert any(call[0] == "cookie" for call in client.requests)


@pytest.mark.parametrize(
    ("query_parameters", "expected_query_parameters"),
    [
        (
            "network_view=default&empty=",
            [("tag", "blue"), ("network_view", "default"), ("empty", "")],
        ),
        ('{"network_view":"default"}', [("tag", "blue"), ("network_view", "default")]),
    ],
)
def test_make_request_registered_action_uses_asset_auth_and_verification(monkeypatch, query_parameters, expected_query_parameters):
    class RequestSession:
        def __init__(self):
            self.call = None
            self.closed = False

        def request(self, *args, **kwargs):
            self.call = (args, kwargs)
            return type("Response", (), {"status_code": 201, "text": '{"ok":true}'})()

        def close(self):
            self.closed = True

    session = RequestSession()

    class RequestClient:
        def __init__(self, asset):
            self.base_url = f"{asset.url}/wapi/v2.3.1"
            self.auth = (asset.username, asset.password)
            self.verify_ssl = asset.verify_server_cert if asset.verify_server_cert is not None else True
            self.session = session

        def request(self, endpoint, *, method, headers, params, data, timeout, verify_ssl):
            return self.session.request(
                method.upper(),
                f"{self.base_url}{endpoint}",
                auth=self.auth,
                headers=headers,
                params=params,
                data=data,
                timeout=timeout,
                verify=verify_ssl,
            )

        def close(self):
            session.close()

    request_action = importlib.import_module("src.actions.make_request")
    monkeypatch.setattr(request_action, "InfobloxClient", RequestClient)
    soar = FakeSoar()
    params = InfobloxMakeRequestParams(
        http_method="GET",
        endpoint="/network?tag=blue",
        query_parameters=query_parameters,
        headers='{"Accept":"application/json"}',
        timeout=12,
    )
    asset = make_asset(verify_server_cert=False)

    before = len(sdk.app.actions_manager.get_results())
    assert sdk.app.actions_manager.get_action("make_request")(params, soar=soar, asset=asset) is True
    result = sdk.app.actions_manager.get_results()[before]

    args, kwargs = session.call
    assert args == ("GET", "https://grid.example/wapi/v2.3.1/network")
    assert kwargs["auth"] == ("api-user", "pwd")
    assert kwargs["verify"] is False
    assert kwargs["timeout"] == 12
    assert kwargs["headers"] == {"Accept": "application/json"}
    assert kwargs["params"] == expected_query_parameters
    assert result.get_data() == [{"status_code": 201, "response_body": '{"ok":true}'}]
    assert soar.message is None
    assert session.closed


def test_make_request_rejects_duplicate_query_keys_before_client_creation(monkeypatch):
    request_action = importlib.import_module("src.actions.make_request")
    params = InfobloxMakeRequestParams(
        http_method="GET",
        endpoint="/network?tag=blue&network_view=old",
        query_parameters='{"network_view":"default"}',
    )
    monkeypatch.setattr(
        request_action,
        "InfobloxClient",
        lambda _asset: pytest.fail("duplicate query keys must fail before client creation"),
    )

    with pytest.raises(ActionFailure, match="specified in both endpoint and query_parameters"):
        request_action.make_request(params, make_asset())


@pytest.mark.parametrize(
    "endpoint",
    [
        "/../../admin",
        "/%2e%2e/%2e%2e/admin",
        "/%252e%252e/%252e%252e/admin",
        r"/..\..\admin",
        "/..;parameter/admin",
        "/network/\x00admin",
    ],
)
def test_make_request_rejects_paths_that_can_escape_wapi(endpoint):
    request_action = importlib.import_module("src.actions.make_request")
    params = InfobloxMakeRequestParams(http_method="GET", endpoint=endpoint)

    with pytest.raises(ActionFailure, match="endpoint path"):
        request_action.make_request(params, make_asset())
