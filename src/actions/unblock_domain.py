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

from typing import Any

from soar_sdk.abstract import SOARClient

from ..asset import Asset
from ..infoblox_client import InfobloxClient
from ._common import _run_action
from ._models import DomainRpzParams, LegacyStringSummary
from ._rpz import _domain_rule_action


def _unblock_domain_handler(client: InfobloxClient, params: DomainRpzParams) -> dict[str, Any]:
    return _domain_rule_action(client, params, block=False)


def unblock_domain(params: DomainRpzParams, soar: SOARClient, asset: Asset):
    return _run_action(params, asset, soar, LegacyStringSummary, _unblock_domain_handler)
