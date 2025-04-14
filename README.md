# Infoblox DDI

Publisher: Splunk \
Connector Version: 2.1.5 \
Product Vendor: Infoblox \
Product Name: Infoblox DDI \
Minimum Product Version: 6.1.0

This app supports various containment and investigative actions on Infoblox Grid Manager

### Configuration variables

This table lists the configuration variables required to operate Infoblox DDI. These variables are specified when configuring a Infoblox DDI asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** | required | string | URL (e.g. https://10.10.10.10) |
**verify_server_cert** | optional | boolean | Verify server certificate |
**username** | required | string | Username |
**password** | required | password | Password |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate credentials provided for connectivity \
[list network view](#action-list-network-view) - List available network views \
[get network info](#action-get-network-info) - List available networks \
[get system info](#action-get-system-info) - Get the leases for the given IP/domain \
[unblock ip](#action-unblock-ip) - Unblock an IP \
[block ip](#action-block-ip) - Block an IP \
[unblock domain](#action-unblock-domain) - Unblock a domain \
[block domain](#action-block-domain) - Block a domain \
[list rpz](#action-list-rpz) - List details of Response Policy Zones \
[list hosts](#action-list-hosts) - List available hosts

## action: 'test connectivity'

Validate credentials provided for connectivity

Type: **test** \
Read only: **True**

Note: Even if the credentials are correct, if Infoblox is configured with an ACL that does not allow Splunk SOAR to authenticate to it, you will receive an authentication failure.

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'list network view'

List available network views

Type: **investigate** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.data.\*.\_ref | string | | networkview/AA1aAa1aaAaa1Aa1aAa:default/true |
action_result.data.\*.comment | string | | Test comment |
action_result.data.\*.is_default | boolean | | True False |
action_result.data.\*.name | string | `infoblox view` | default |
action_result.summary.total_network_view | numeric | | 2 |
action_result.message | string | | Total network view: 2 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get network info'

List available networks

Type: **investigate** \
Read only: **True**

Get network information for an IP or IP range (in CIDR notation). If an IP is not provided, return all network ranges.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | optional | IP or IP network (CIDR notation) | string | `ip` |
**network_view** | optional | Network view | string | `infoblox view` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.ip | string | `ip` | 10.0.0.5 |
action_result.parameter.network_view | string | `infoblox view` | Internal Networks |
action_result.data.\*.\_ref | string | | range/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:10.0.0.1/10.254.254.254/Internal%20Networks |
action_result.data.\*.comment | string | | Example of a comment |
action_result.data.\*.network | string | `ip` | 10.0.0.0/8 |
action_result.data.\*.network_view | string | `infoblox view` | Internal Networks |
action_result.summary.number_of_matching_networks | numeric | | 1 |
action_result.message | string | | Number of matching networks: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get system info'

Get the leases for the given IP/domain

Type: **investigate** \
Read only: **True**

Default value for <b>network_view</b> is 'default'. This action will not fetch system information of a host that has static IP and belongs to a non-default network view.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** | required | IP/Hostname | string | `ip` `host name` |
**network_view** | optional | Network view | string | `infoblox view` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.ip_hostname | string | `ip` `host name` | 10.0.0.5 |
action_result.parameter.network_view | string | `infoblox view` | Internal Networks |
action_result.data.\*.\_ref | string | | lease/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:10.0.0.5/default |
action_result.data.\*.address | string | `ip` | 10.0.0.5 |
action_result.data.\*.billing_class | string | | |
action_result.data.\*.binding_state | string | | FREE |
action_result.data.\*.client_hostname | string | `host name` | |
action_result.data.\*.cltt | string | | 2010-10-10 10:11:12 |
action_result.data.\*.ends | string | | 2010-10-10 12:11:12 |
action_result.data.\*.hardware | string | `mac address` | 0a:10:10:a0:a0:10 |
action_result.data.\*.ipv6_duid | string | | |
action_result.data.\*.ipv6_iaid | string | | |
action_result.data.\*.ipv6_preferred_lifetime | numeric | | 604800 |
action_result.data.\*.ipv6_prefix_bits | numeric | | 48 |
action_result.data.\*.is_invalid_mac | boolean | | True False |
action_result.data.\*.network | string | | |
action_result.data.\*.network_view | string | `infoblox view` | default |
action_result.data.\*.never_ends | boolean | | True False |
action_result.data.\*.never_starts | boolean | | True False |
action_result.data.\*.next_binding_state | string | | ACTIVE |
action_result.data.\*.on_commit | string | | |
action_result.data.\*.on_expiry | string | | |
action_result.data.\*.on_release | string | | |
action_result.data.\*.option | string | | |
action_result.data.\*.os | string | | Linux |
action_result.data.\*.protocol | string | | IPV4 |
action_result.data.\*.remote_id | string | | |
action_result.data.\*.served_by | string | `ip` | 10.0.0.7 |
action_result.data.\*.server_host_name | string | `host name` | test-01.lab.test.local |
action_result.data.\*.starts | string | | 2010-10-10 10:11:12 |
action_result.data.\*.tsfp | string | | 1504274705 |
action_result.data.\*.tstp | string | | 1504274905 |
action_result.data.\*.uid | string | | |
action_result.data.\*.username | string | | |
action_result.data.\*.variable | string | | lt="undefined" |
action_result.summary.binding_state | string | | |
action_result.summary.is_static_ip | boolean | | True False |
action_result.summary.mac_address | string | `mac address` | 0a:10:10:a0:a0:10 |
action_result.summary.never_ends | boolean | | True False |
action_result.message | string | | Mac address: 0a:10:10:a0:a0:10, Is static ip: True |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'unblock ip'

Unblock an IP

Type: **correct** \
Read only: **False**

This action uses a multistep approach to unblock the IP:<ul><li>Check if RPZ exists with policy override 'None(GIVEN)'. If not, action will fail.</li><li>Remove the RPZ rule 'Block IP Address (No Such Domain)' with the specified IP address.</ul>Default value for <b>network_view</b> is 'default'.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP/CIDR to unblock | string | `ip` |
**rp_zone** | required | FQDN of response policy zone | string | `infoblox rpz` |
**network_view** | optional | Network view | string | `infoblox view` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.ip | string | `ip` | 10.0.0.5 |
action_result.parameter.network_view | string | `infoblox view` | Internal Networks |
action_result.parameter.rp_zone | string | `infoblox rpz` | testzone |
action_result.data.\*.reference_link | string | | record:rpz:cname:ipaddress/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:10.0.0.5.test_zone/default |
action_result.summary | string | | |
action_result.message | string | | IP/CIDR unblocked successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'block ip'

Block an IP

Type: **contain** \
Read only: **False**

This action blocks the IP by creating an appropriate RPZ. It blocks the domain by modifying the response of the DNS recursive query. The domain will not resolve the IP address/network. If all the IP addresses of the domain are blocked, the domain will be blocked. Each RPZ can have various rules associated with it. The response of a recursive query is modified if it matches any of the RPZ rules. The responses are first matched with the RPZ rules, and if there is a match, the rule defined at the RPZ level override is used. The override depends on the order of RPZ. The RPZs are prioritized in ascending order. Ensure that the specified RPZ has policy override 'None(GIVEN)', so that rule defined at RPZ level override is used. This action uses a multistep approach to block the IP:<ul><li>Check if RPZ exists with policy override 'None(GIVEN)'. If not, action will fail.</li><li>Add the RPZ rule 'Block IP Address (No Such Domain)' with the specified IP address. If another RPZ rule with a specified IP already exists with other than (No Such Domain) policy, the action will fail.</li></ul>Default value for <b>network_view</b> is 'default'.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP/CIDR to block | string | `ip` |
**rp_zone** | required | FQDN of response policy zone | string | `infoblox rpz` |
**network_view** | optional | Network view | string | `infoblox view` |
**comment** | optional | Comment (maximum 256 characters) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.comment | string | | Test comment |
action_result.parameter.ip | string | `ip` | 10.0.0.5 |
action_result.parameter.network_view | string | `infoblox view` | Internal Networks |
action_result.parameter.rp_zone | string | `infoblox rpz` | testzone |
action_result.data.\*.reference_link | string | | record:rpz:cname:ipaddress/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:10.0.0.5.test_zone/default |
action_result.summary | string | | |
action_result.message | string | | IP/CIDR blocked successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'unblock domain'

Unblock a domain

Type: **correct** \
Read only: **False**

This action uses a multistep approach to unblock the domain:<ul><li>Check if RPZ exists with policy override 'None(GIVEN)'. If not, action will fail.</li><li>Remove the RPZ rule 'Block Domain Name (No Such Domain)' with the specified domain.</ul>Default value for <b>network_view</b> is 'default'.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** | required | Domain to unblock | string | `domain` `url` |
**rp_zone** | required | FQDN of response policy zone | string | `infoblox rpz` |
**network_view** | optional | Network view | string | `infoblox view` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.domain | string | `domain` `url` | example.com |
action_result.parameter.network_view | string | `infoblox view` | Internal Networks |
action_result.parameter.rp_zone | string | `infoblox rpz` | testzone |
action_result.data.\*.reference_link | string | | record:rpz:cname/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:www.test.abc.test_zone/default |
action_result.summary | string | | |
action_result.message | string | | Domain unblocked successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'block domain'

Block a domain

Type: **contain** \
Read only: **False**

This action blocks the domain by creating appropriate RPZ. Each RPZ can have various rules associated with it. The response of a recursive query is modified if it matches any of the RPZ rules. The responses are first matched with the RPZ rules, and if there is a match, the rule defined at the RPZ level override is used. The override depends on the order of RPZ. The RPZs are prioritized in ascending order. Ensure that the specified RPZ has policy override 'None(GIVEN)', so that rule defined at RPZ level override is used. This action uses a multistep approach to block the domain:<ul><li>Check if RPZ exists with policy override 'None(GIVEN)'. If not, action will fail.</li><li>Add the RPZ rule 'Block Domain Name (No Such Domain)' with the specified domain. If another RPZ rule with a specified domain already exists with other than (No Such Domain) policy, the action will fail.</li></ul>Default value for <b>network_view</b> is 'default'.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** | required | Domain to block | string | `domain` `url` |
**rp_zone** | required | FQDN of response policy zone | string | `infoblox rpz` |
**network_view** | optional | Network view | string | `infoblox view` |
**comment** | optional | Comment (maximum 256 characters) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.comment | string | | Test comment |
action_result.parameter.domain | string | `domain` `url` | example.com |
action_result.parameter.network_view | string | `infoblox view` | Internal Networks |
action_result.parameter.rp_zone | string | `infoblox rpz` | testzone |
action_result.data.\*.reference_link | string | | record:rpz:cname/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:www.test.abc.test_zone/default |
action_result.summary | string | | |
action_result.message | string | | Domain blocked successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list rpz'

List details of Response Policy Zones

Type: **investigate** \
Read only: **True**

Default value for <b>network_view</b> is 'default'.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**network_view** | optional | Network view | string | `infoblox view` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.network_view | string | `infoblox view` | Internal Networks |
action_result.data.\*.\_ref | string | | zone_rp/AA1aAa1aaAaa1Aa1aAa:test/default |
action_result.data.\*.comment | string | | Test comment |
action_result.data.\*.disable | boolean | | True False |
action_result.data.\*.fqdn | string | `infoblox rpz` | test_fqdn |
action_result.data.\*.network_view | string | `infoblox view` | default |
action_result.data.\*.ns_group | string | | PRIMARY |
action_result.data.\*.primary_type | string | | Grid |
action_result.data.\*.rpz_last_updated_time | string | | |
action_result.data.\*.rpz_policy | string | | GIVEN |
action_result.data.\*.rpz_priority | numeric | | 1 |
action_result.data.\*.rpz_severity | string | | MAJOR |
action_result.data.\*.rpz_type | string | | LOCAL |
action_result.data.\*.substitute_name | string | | test_name |
action_result.summary.total_response_policy_zones | numeric | | 3 |
action_result.message | string | | Total response policy zones: 3 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list hosts'

List available hosts

Type: **investigate** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.data.\*.\_ref | string | | record:a/AA1aAa1aaAaa1Aa1aAaAA1aAa1aaAaa1Aa1aAa:test_nv_a_record.test_zone/default.dns |
action_result.data.\*.discovered_data.first_discovered | numeric | | 1495071666 |
action_result.data.\*.discovered_data.last_discovered | numeric | | 1495071666 |
action_result.data.\*.discovered_data.mac_address | string | `mac address` | 0a:10:10:a0:a0:10 |
action_result.data.\*.discovered_data.os | string | | Linux |
action_result.data.\*.ip | string | `ip` | 10.0.0.5 |
action_result.data.\*.name | string | `host name` | test |
action_result.data.\*.view | string | `infoblox view` | External DNS |
action_result.data.\*.zone | string | | example.com |
action_result.summary.total_hosts | numeric | | 1122 |
action_result.message | string | | Total hosts: 1122 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
