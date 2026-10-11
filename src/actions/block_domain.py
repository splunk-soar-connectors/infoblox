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

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..consts import INFOBLOX_NETWORK_VIEW_DEFAULT
from ..infoblox_client import InfobloxClient
from ._common import LegacyStringSummary, _run_action
from ._rpz import _domain_rule_action


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
        default=INFOBLOX_NETWORK_VIEW_DEFAULT,
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


def _block_domain_handler(client: InfobloxClient, params: BlockDomainParams) -> dict[str, Any]:
    return _domain_rule_action(client, params, block=True, comment=params.comment)


def block_domain(params: BlockDomainParams, soar: SOARClient, asset: Asset):
    return _run_action(params, asset, soar, LegacyStringSummary, _block_domain_handler)
