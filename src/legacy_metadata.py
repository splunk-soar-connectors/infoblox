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
"""Compatibility metadata overrides for fields the SDK serializer normalizes."""

from typing import Any

from soar_sdk.app import App
from soar_sdk.meta.actions import ActionMeta


LEGACY_MESSAGE_METADATA = {
    "list_network_view": {"example_values": ["Total network view: 2"]},
    "get_network_info": {"example_values": ["Number of matching networks: 1"]},
    "get_system_info": {"example_values": ["Mac address: 0a:10:10:a0:a0:10, Is static ip: True"]},
    "unblock_ip": {
        "example_values": ["IP/CIDR unblocked successfully"],
        "column_name": "Unblock Status",
        "column_order": 3,
    },
    "block_ip": {
        "example_values": ["IP/CIDR blocked successfully"],
        "column_name": "Block Status",
        "column_order": 3,
    },
    "unblock_domain": {
        "example_values": ["Domain unblocked successfully"],
        "column_name": "Unblock Status",
        "column_order": 3,
    },
    "block_domain": {
        "example_values": ["Domain blocked successfully"],
        "column_name": "Block Status",
        "column_order": 3,
    },
    "list_rpz": {"example_values": ["Total response policy zones: 3"]},
    "list_hosts": {"example_values": ["Total hosts: 1122"]},
}

LEGACY_PARAMETER_EXAMPLES = {
    "get_network_info": {
        "ip": ["10.0.0.5"],
        "network_view": ["Internal Networks"],
    },
    "get_system_info": {
        "ip_hostname": ["10.0.0.5"],
        "network_view": ["Internal Networks"],
    },
    "unblock_ip": {
        "ip": ["10.0.0.5"],
        "network_view": ["Internal Networks"],
        "rp_zone": ["testzone"],
    },
    "block_ip": {
        "comment": ["Test comment"],
        "ip": ["10.0.0.5"],
        "network_view": ["Internal Networks"],
        "rp_zone": ["testzone"],
    },
    "unblock_domain": {
        "domain": ["example.com"],
        "network_view": ["Internal Networks"],
        "rp_zone": ["testzone"],
    },
    "block_domain": {
        "comment": ["Test comment"],
        "domain": ["example.com"],
        "network_view": ["Internal Networks"],
        "rp_zone": ["testzone"],
    },
    "list_rpz": {"network_view": ["Internal Networks"]},
}

GET_SYSTEM_INFO_COLUMN_ORDERS = {
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

# Keep the serialized output metadata in the same sequence as the legacy
# manifest. Field properties and table column_order are separate contracts;
# some clients still consume this list in declaration order.
LEGACY_OUTPUT_ORDER = {
    "list_network_view": (
        "action_result.status",
        "action_result.data.*._ref",
        "action_result.data.*.comment",
        "action_result.data.*.is_default",
        "action_result.data.*.name",
        "action_result.summary.total_network_view",
        "action_result.message",
        "summary.total_objects",
        "summary.total_objects_successful",
    ),
    "get_network_info": (
        "action_result.status",
        "action_result.parameter.ip",
        "action_result.parameter.network_view",
        "action_result.data.*._ref",
        "action_result.data.*.comment",
        "action_result.data.*.network",
        "action_result.data.*.network_view",
        "action_result.summary.number_of_matching_networks",
        "action_result.message",
        "summary.total_objects",
        "summary.total_objects_successful",
    ),
    "get_system_info": (
        "action_result.status",
        "action_result.parameter.ip_hostname",
        "action_result.parameter.network_view",
        "action_result.data.*._ref",
        "action_result.data.*.address",
        "action_result.data.*.billing_class",
        "action_result.data.*.binding_state",
        "action_result.data.*.client_hostname",
        "action_result.data.*.cltt",
        "action_result.data.*.ends",
        "action_result.data.*.hardware",
        "action_result.data.*.ipv6_duid",
        "action_result.data.*.ipv6_iaid",
        "action_result.data.*.ipv6_preferred_lifetime",
        "action_result.data.*.ipv6_prefix_bits",
        "action_result.data.*.is_invalid_mac",
        "action_result.data.*.network",
        "action_result.data.*.network_view",
        "action_result.data.*.never_ends",
        "action_result.data.*.never_starts",
        "action_result.data.*.next_binding_state",
        "action_result.data.*.on_commit",
        "action_result.data.*.on_expiry",
        "action_result.data.*.on_release",
        "action_result.data.*.option",
        "action_result.data.*.os",
        "action_result.data.*.protocol",
        "action_result.data.*.remote_id",
        "action_result.data.*.served_by",
        "action_result.data.*.server_host_name",
        "action_result.data.*.starts",
        "action_result.data.*.tsfp",
        "action_result.data.*.tstp",
        "action_result.data.*.uid",
        "action_result.data.*.username",
        "action_result.data.*.variable",
        "action_result.summary.binding_state",
        "action_result.summary.is_static_ip",
        "action_result.summary.mac_address",
        "action_result.summary.never_ends",
        "action_result.message",
        "summary.total_objects",
        "summary.total_objects_successful",
    ),
    "unblock_ip": (
        "action_result.status",
        "action_result.parameter.ip",
        "action_result.parameter.network_view",
        "action_result.parameter.rp_zone",
        "action_result.data.*.reference_link",
        "action_result.summary",
        "action_result.message",
        "summary.total_objects",
        "summary.total_objects_successful",
    ),
    "block_ip": (
        "action_result.status",
        "action_result.parameter.comment",
        "action_result.parameter.ip",
        "action_result.parameter.network_view",
        "action_result.parameter.rp_zone",
        "action_result.data.*.reference_link",
        "action_result.summary",
        "action_result.message",
        "summary.total_objects",
        "summary.total_objects_successful",
    ),
    "unblock_domain": (
        "action_result.status",
        "action_result.parameter.domain",
        "action_result.parameter.network_view",
        "action_result.parameter.rp_zone",
        "action_result.data.*.reference_link",
        "action_result.summary",
        "action_result.message",
        "summary.total_objects",
        "summary.total_objects_successful",
    ),
    "block_domain": (
        "action_result.status",
        "action_result.parameter.comment",
        "action_result.parameter.domain",
        "action_result.parameter.network_view",
        "action_result.parameter.rp_zone",
        "action_result.data.*.reference_link",
        "action_result.summary",
        "action_result.message",
        "summary.total_objects",
        "summary.total_objects_successful",
    ),
    "list_rpz": (
        "action_result.status",
        "action_result.parameter.network_view",
        "action_result.data.*._ref",
        "action_result.data.*.comment",
        "action_result.data.*.disable",
        "action_result.data.*.fqdn",
        "action_result.data.*.network_view",
        "action_result.data.*.ns_group",
        "action_result.data.*.primary_type",
        "action_result.data.*.rpz_last_updated_time",
        "action_result.data.*.rpz_policy",
        "action_result.data.*.rpz_priority",
        "action_result.data.*.rpz_severity",
        "action_result.data.*.rpz_type",
        "action_result.data.*.substitute_name",
        "action_result.summary.total_response_policy_zones",
        "action_result.message",
        "summary.total_objects",
        "summary.total_objects_successful",
    ),
    "list_hosts": (
        "action_result.status",
        "action_result.data.*._ref",
        "action_result.data.*.discovered_data.first_discovered",
        "action_result.data.*.discovered_data.last_discovered",
        "action_result.data.*.discovered_data.mac_address",
        "action_result.data.*.discovered_data.os",
        "action_result.data.*.ip",
        "action_result.data.*.name",
        "action_result.data.*.view",
        "action_result.data.*.zone",
        "action_result.summary.total_hosts",
        "action_result.message",
        "summary.total_objects",
        "summary.total_objects_successful",
    ),
}


class LegacyOutputActionMeta(ActionMeta):
    """Restore legacy output metadata after the SDK builds its schema."""

    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        metadata = super().model_dump(*args, **kwargs)
        parameters = metadata.get("parameters") or {}
        for parameter in parameters.values():
            # These are SDK serialization defaults, not fields present in the
            # legacy manifest. Removing them here changes metadata only; the
            # Params models retain their validation and runtime defaults.
            parameter.pop("name", None)
            for key in ("required", "allow_list", "primary"):
                if parameter.get(key) is False:
                    parameter.pop(key)

        output = metadata.get("output")
        if output is None:
            return metadata

        for field in output:
            datapath = field["data_path"]
            if datapath.startswith("action_result.parameter."):
                parameter = datapath.removeprefix("action_result.parameter.")
                examples = LEGACY_PARAMETER_EXAMPLES.get(self.identifier, {}).get(parameter)
                if examples is not None:
                    field["example_values"] = examples
            if datapath == "action_result.status":
                field["example_values"] = ["success", "failed"]
            elif datapath == "action_result.message":
                field.update(LEGACY_MESSAGE_METADATA[self.identifier])

            if self.identifier == "get_system_info" and datapath in GET_SYSTEM_INFO_COLUMN_ORDERS:
                field["column_order"] = GET_SYSTEM_INFO_COLUMN_ORDERS[datapath]

        order = {path: index for index, path in enumerate(LEGACY_OUTPUT_ORDER.get(self.identifier, ()))}
        if order:
            indexed_output = enumerate(output)
            metadata["output"] = [
                field
                for _, field in sorted(
                    indexed_output,
                    key=lambda item: (order.get(item[1]["data_path"], len(order)), item[0]),
                )
            ]

        return metadata


def apply_legacy_output_metadata(app: App) -> None:
    """Wrap legacy action metadata with exact manifest compatibility overrides."""
    for action in app.get_actions().values():
        if action.meta.identifier not in LEGACY_MESSAGE_METADATA:
            continue
        metadata = action.meta
        action.meta = LegacyOutputActionMeta(
            action=metadata.action,
            identifier=metadata.identifier,
            description=metadata.description,
            type=metadata.type,
            read_only=metadata.read_only,
            versions=metadata.versions,
            verbose=metadata.verbose,
            parameters=metadata.parameters,
            output=metadata.output,
            render_as=metadata.render_as,
            view_handler=metadata.view_handler,
            summary_type=metadata.summary_type,
            lock=metadata.lock,
            enable_concurrency_lock=metadata.enable_concurrency_lock,
        )
