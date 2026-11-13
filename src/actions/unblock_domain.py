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
"""unblock domain action implementation."""

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..consts import INFOBLOX_NETWORK_VIEW_DEFAULT
from .common import run_action
from .rpz import domain_rule_action


class UnblockDomainParams(Params):
    """Inputs for unblocking a domain in an Infoblox response policy zone."""

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
    network_view: str = Param(
        description="Network view",
        required=False,
        default=INFOBLOX_NETWORK_VIEW_DEFAULT,
        primary=True,
        cef_types=["infoblox view"],
        column_name="Network View",
    )


class UnblockDomainOutput(ActionOutput):
    reference_link: str | None = OutputField(
        example_values=["record:rpz:cname/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:www.test.abc.test_zone/default"]
    )


def unblock_domain(params: UnblockDomainParams, soar: SOARClient, asset: Asset):
    outcome = run_action(params, asset, domain_rule_action, block=False)
    message = outcome.get("message", "")
    soar.set_message(message)
    soar.set_summary(ActionOutput(**outcome.get("summary", {})))
    if not outcome.get("success", True):
        return False, message, params.model_dump(by_alias=True)
    return [UnblockDomainOutput(**row) for row in outcome.get("data", [])]
