### Additional behavior notes

Lease and RPZ last-updated timestamps are displayed in the local timezone of the SOAR worker.

### Make request WAPI version

The **make request** action uses WAPI `2.3.1` by default, for example with endpoint `/network`.
To select another version on the configured Grid, include it in the endpoint, for example
`/wapi/v2.13.6/network`. The Grid determines whether that version and operation are supported
and permitted for the configured credentials. Built-in actions continue to use WAPI `2.3.1`.
Absolute URLs and paths that escape the selected WAPI version are rejected.
