### Additional behavior notes

Lease and RPZ last-updated timestamps are displayed in the local timezone of the SOAR worker.

### SDK migration notes

Test connectivity's success message changed from "Connectivity test succeeded" to "Test connectivity successful".
Update tests or playbooks that compare the exact message; checking the action's success status is preferable.
