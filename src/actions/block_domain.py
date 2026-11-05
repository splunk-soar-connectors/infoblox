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
"""block domain action implementation."""

from typing import Any

from pydantic import model_validator
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..consts import INFOBLOX_NETWORK_VIEW_DEFAULT
from .common import run_action
from .rpz import domain_rule_action


class BlockDomainParams(Params):
    """Inputs for blocking a domain in an Infoblox response policy zone."""

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
    network_view: str | None = Param(
        description="Network view",
        default=INFOBLOX_NETWORK_VIEW_DEFAULT,
        primary=True,
        cef_types=["infoblox view"],
        column_name="Network View",
    )

    comment: str | None = Param(description="Comment (maximum 256 characters)", required=False)

    @model_validator(mode="before")
    @classmethod
    def _default_network_view_when_omitted(cls, values: Any) -> Any:
        """Use the legacy default only when network_view was not provided."""
        if isinstance(values, dict) and "network_view" not in values:
            return {**values, "network_view": INFOBLOX_NETWORK_VIEW_DEFAULT}
        return values


class BlockDomainOutput(ActionOutput):
    reference_link: str | None = OutputField(
        example_values=["record:rpz:cname/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:www.test.abc.test_zone/default"]
    )


def block_domain(params: BlockDomainParams, soar: SOARClient, asset: Asset):
    return run_action(
        params,
        asset,
        soar,
        ActionOutput,
        domain_rule_action,
        output_type=BlockDomainOutput,
        block=True,
        comment=params.comment,
    )
