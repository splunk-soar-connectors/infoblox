### Python compatibility

Splunk SOAR SDK `7.1.2` requires Python `>=3.13,<3.16`, excluding `3.14.*` (Python 3.13 and 3.15).

See the [SDK package requirements](https://pypi.org/project/splunk-soar-sdk/7.1.2/).

### Additional behavior notes

Lease and RPZ last-updated timestamps are displayed in the local timezone of the SOAR worker.

### SDK migration notes

Test connectivity's success message changed from "Connectivity test succeeded" to "Test connectivity successful".
Update tests or playbooks that compare the exact message; checking the action's success status is preferable.
