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
"""Shared action execution, validation, and result helpers."""

import ipaddress
import socket
from typing import Any

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, ActionResult
from soar_sdk.logging import getLogger
from soar_sdk.params import Params

from ..asset import Asset
from ..consts import INFOBLOX_IP_VALIDATION_FAILED
from ..infoblox_client import InfobloxApiError, InfobloxClient, exception_message


logger = getLogger()


def _is_ipv6(value: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, value)
    except OSError:
        return False
    return True


def _is_ip(value: str) -> bool:
    try:
        if "/" in value:
            address, prefix = value.split("/", 1)
            prefix_size = int(prefix)
        else:
            address, prefix_size = value, 0
        parsed = ipaddress.ip_address(address)
    except (ValueError, TypeError) as error:
        logger.debug(f"{INFOBLOX_IP_VALIDATION_FAILED}. {exception_message(error)}")
        return False
    if ":" in address and not _is_ipv6(address):
        logger.debug(INFOBLOX_IP_VALIDATION_FAILED)
        return False
    if not 0 <= prefix_size <= parsed.max_prefixlen:
        logger.debug(INFOBLOX_IP_VALIDATION_FAILED)
        return False
    return True


def _is_address(value: str) -> bool:
    """True only for a host address, matching the legacy lease lookup test."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return ":" not in value or _is_ipv6(value)


def _params_dict(params: Params) -> dict[str, Any]:
    return params.model_dump(exclude_unset=True, by_alias=True)


def _action_result(
    params: Params,
    soar: SOARClient,
    summary_type: type[ActionOutput],
    *,
    success: bool = True,
    message: str = "",
    data: list[dict[str, Any]] | None = None,
    summary: dict[str, Any] | None = None,
) -> ActionResult:
    """Build a raw result so WAPI value types and omitted keys stay intact."""
    summary_data = dict(summary or {})
    soar.set_message(message)
    soar.set_summary(summary_type.model_construct(**summary_data))
    result = ActionResult(success, message, _params_dict(params))
    for row in data or []:
        result.add_data(row)
    result.set_summary(summary_data)
    return result


def _run_action(
    params: Params,
    asset: Asset,
    soar: SOARClient,
    summary_type: type[ActionOutput],
    handler: Any,
) -> ActionResult:
    client = InfobloxClient(asset)
    try:
        outcome = handler(client, params)
    except InfobloxApiError as error:
        outcome = {
            "success": False,
            "message": str(error),
            "data": [],
            "summary": {},
        }
    except Exception as error:
        logger.exception("Unexpected Infoblox action failure")
        outcome = {
            "success": False,
            "message": f"Exception occurred. {exception_message(error)}",
            "data": [],
            "summary": {},
        }

    try:
        client.logout()
    except InfobloxApiError as error:
        if outcome.get("success", True):
            outcome = {
                **outcome,
                "success": False,
                "message": str(error),
            }
    finally:
        client.close()

    return _action_result(params, soar, summary_type, **outcome)
