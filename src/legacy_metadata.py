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


class LegacyOutputActionMeta(ActionMeta):
    """Restore legacy output metadata after the SDK builds its schema."""

    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        metadata = super().model_dump(*args, **kwargs)
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
