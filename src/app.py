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
"""Splunk SOAR SDK application entry point for Infoblox DDI."""

from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Params

from .actions import register_actions
from .actions.connectivity import _test_connectivity_handler
from .asset import Asset
from .infoblox_client import InfobloxApiError, InfobloxClient, exception_message
from .legacy_metadata import apply_legacy_output_metadata


logger = getLogger()


def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    """Check the Infoblox WAPI connection using the configured asset."""
    logger.progress("Logging into device")
    client = InfobloxClient(asset)
    try:
        outcome = _test_connectivity_handler(client, Params())
    except Exception as error:
        logger.exception("Unexpected Infoblox connectivity failure")
        outcome = {
            "success": False,
            "message": f"Exception occurred. {exception_message(error)}",
        }

    try:
        client.logout()
    except InfobloxApiError as error:
        if outcome.get("success", False):
            outcome = {**outcome, "success": False, "message": str(error)}
    finally:
        client.close()

    if not outcome.get("success", False):
        logger.progress("Connectivity test failed")
        raise ActionFailure(outcome.get("message") or "Connectivity test failed")
    logger.progress("Connectivity test succeeded")


def create_infoblox_app() -> App:
    """Create the Infoblox SDK app and register its actions and connectivity hook."""
    app = App(
        name="Infoblox DDI",
        app_type="network security",
        logo="logo_infoblox.svg",
        logo_dark="logo_infoblox_dark.svg",
        product_vendor="Infoblox",
        product_name="Infoblox DDI",
        publisher="Splunk",
        appid="5ec38a6e-18c3-4cc3-ab47-2754b56aea50",
        fips_compliant=False,
        asset_cls=Asset,
    )
    register_actions(app)
    app.test_connectivity()(test_connectivity)
    apply_legacy_output_metadata(app)
    return app


app: App = create_infoblox_app()


if __name__ == "__main__":
    app.cli()
