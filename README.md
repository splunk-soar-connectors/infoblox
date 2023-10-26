[comment]: # "Auto-generated SOAR connector documentation"
# Infoblox DDI

Publisher: Splunk  
Connector Version: 2\.1\.4  
Product Vendor: Infoblox  
Product Name: Infoblox DDI  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

This app supports various containment and investigative actions on Infoblox Grid Manager

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Infoblox DDI asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | URL \(e\.g\. https\://10\.10\.10\.10\)
**verify\_server\_cert** |  optional  | boolean | Verify server certificate
**username** |  required  | string | Username
**password** |  required  | password | Password

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate credentials provided for connectivity  
[list network view](#action-list-network-view) - List available network views  
[get network info](#action-get-network-info) - List available networks  
[get system info](#action-get-system-info) - Get the leases for the given IP/domain  
[unblock ip](#action-unblock-ip) - Unblock an IP  
[block ip](#action-block-ip) - Block an IP  
[unblock domain](#action-unblock-domain) - Unblock a domain  
[block domain](#action-block-domain) - Block a domain  
[list rpz](#action-list-rpz) - List details of Response Policy Zones  
[list hosts](#action-list-hosts) - List available hosts  

## action: 'test connectivity'
Validate credentials provided for connectivity

Note: Even if the credentials are correct, if Infoblox
is configured with an ACL that does not allow Splunk
SOAR to authenticate to it, you will receive an
authentication failure.

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list network view'
List available network views

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.\_ref | string | 
action\_result\.data\.\*\.comment | string | 
action\_result\.data\.\*\.is\_default | boolean | 
action\_result\.data\.\*\.name | string |  `infoblox view` 
action\_result\.summary\.total\_network\_view | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get network info'
List available networks

Type: **investigate**  
Read only: **True**

Get network information for an IP or IP range \(in CIDR notation\)\. If an IP is not provided, return all network ranges\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  optional  | IP or IP network \(CIDR notation\) | string |  `ip` 
**network\_view** |  optional  | Network view | string |  `infoblox view` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.network\_view | string |  `infoblox view` 
action\_result\.data\.\*\.\_ref | string | 
action\_result\.data\.\*\.comment | string | 
action\_result\.data\.\*\.network | string |  `ip` 
action\_result\.data\.\*\.network\_view | string |  `infoblox view` 
action\_result\.summary\.number\_of\_matching\_networks | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get system info'
Get the leases for the given IP/domain

Type: **investigate**  
Read only: **True**

Default value for <b>network\_view</b> is 'default'\. This action will not fetch system information of a host that has static IP and belongs to a non\-default network view\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | IP/Hostname | string |  `ip`  `host name` 
**network\_view** |  optional  | Network view | string |  `infoblox view` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.network\_view | string |  `infoblox view` 
action\_result\.data\.\*\.\_ref | string | 
action\_result\.data\.\*\.address | string |  `ip` 
action\_result\.data\.\*\.billing\_class | string | 
action\_result\.data\.\*\.binding\_state | string | 
action\_result\.data\.\*\.client\_hostname | string |  `host name` 
action\_result\.data\.\*\.cltt | string | 
action\_result\.data\.\*\.ends | string | 
action\_result\.data\.\*\.hardware | string |  `mac address` 
action\_result\.data\.\*\.ipv6\_duid | string | 
action\_result\.data\.\*\.ipv6\_iaid | string | 
action\_result\.data\.\*\.ipv6\_preferred\_lifetime | numeric | 
action\_result\.data\.\*\.ipv6\_prefix\_bits | numeric | 
action\_result\.data\.\*\.is\_invalid\_mac | boolean | 
action\_result\.data\.\*\.network | string | 
action\_result\.data\.\*\.network\_view | string |  `infoblox view` 
action\_result\.data\.\*\.never\_ends | boolean | 
action\_result\.data\.\*\.never\_starts | boolean | 
action\_result\.data\.\*\.next\_binding\_state | string | 
action\_result\.data\.\*\.on\_commit | string | 
action\_result\.data\.\*\.on\_expiry | string | 
action\_result\.data\.\*\.on\_release | string | 
action\_result\.data\.\*\.option | string | 
action\_result\.data\.\*\.os | string | 
action\_result\.data\.\*\.protocol | string | 
action\_result\.data\.\*\.remote\_id | string | 
action\_result\.data\.\*\.served\_by | string |  `ip` 
action\_result\.data\.\*\.server\_host\_name | string |  `host name` 
action\_result\.data\.\*\.starts | string | 
action\_result\.data\.\*\.tsfp | string | 
action\_result\.data\.\*\.tstp | string | 
action\_result\.data\.\*\.uid | string | 
action\_result\.data\.\*\.username | string | 
action\_result\.data\.\*\.variable | string | 
action\_result\.summary\.binding\_state | string | 
action\_result\.summary\.is\_static\_ip | boolean | 
action\_result\.summary\.mac\_address | string |  `mac address` 
action\_result\.summary\.never\_ends | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unblock ip'
Unblock an IP

Type: **correct**  
Read only: **False**

This action uses a multistep approach to unblock the IP\:<ul><li>Check if RPZ exists with policy override 'None\(GIVEN\)'\. If not, action will fail\.</li><li>Remove the RPZ rule 'Block IP Address \(No Such Domain\)' with the specified IP address\.</ul>Default value for <b>network\_view</b> is 'default'\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP/CIDR to unblock | string |  `ip` 
**rp\_zone** |  required  | FQDN of response policy zone | string |  `infoblox rpz` 
**network\_view** |  optional  | Network view | string |  `infoblox view` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.network\_view | string |  `infoblox view` 
action\_result\.parameter\.rp\_zone | string |  `infoblox rpz` 
action\_result\.data\.\*\.reference\_link | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'block ip'
Block an IP

Type: **contain**  
Read only: **False**

This action blocks the IP by creating an appropriate RPZ\. It blocks the domain by modifying the response of the DNS recursive query\. The domain will not resolve the IP address/network\. If all the IP addresses of the domain are blocked, the domain will be blocked\. Each RPZ can have various rules associated with it\. The response of a recursive query is modified if it matches any of the RPZ rules\. The responses are first matched with the RPZ rules, and if there is a match, the rule defined at the RPZ level override is used\. The override depends on the order of RPZ\. The RPZs are prioritized in ascending order\. Ensure that the specified RPZ has policy override 'None\(GIVEN\)', so that rule defined at RPZ level override is used\. This action uses a multistep approach to block the IP\:<ul><li>Check if RPZ exists with policy override 'None\(GIVEN\)'\. If not, action will fail\.</li><li>Add the RPZ rule 'Block IP Address \(No Such Domain\)' with the specified IP address\. If another RPZ rule with a specified IP already exists with other than \(No Such Domain\) policy, the action will fail\.</li></ul>Default value for <b>network\_view</b> is 'default'\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP/CIDR to block | string |  `ip` 
**rp\_zone** |  required  | FQDN of response policy zone | string |  `infoblox rpz` 
**network\_view** |  optional  | Network view | string |  `infoblox view` 
**comment** |  optional  | Comment \(maximum 256 characters\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.network\_view | string |  `infoblox view` 
action\_result\.parameter\.rp\_zone | string |  `infoblox rpz` 
action\_result\.data\.\*\.reference\_link | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unblock domain'
Unblock a domain

Type: **correct**  
Read only: **False**

This action uses a multistep approach to unblock the domain\:<ul><li>Check if RPZ exists with policy override 'None\(GIVEN\)'\. If not, action will fail\.</li><li>Remove the RPZ rule 'Block Domain Name \(No Such Domain\)' with the specified domain\.</ul>Default value for <b>network\_view</b> is 'default'\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to unblock | string |  `domain`  `url` 
**rp\_zone** |  required  | FQDN of response policy zone | string |  `infoblox rpz` 
**network\_view** |  optional  | Network view | string |  `infoblox view` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.parameter\.network\_view | string |  `infoblox view` 
action\_result\.parameter\.rp\_zone | string |  `infoblox rpz` 
action\_result\.data\.\*\.reference\_link | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'block domain'
Block a domain

Type: **contain**  
Read only: **False**

This action blocks the domain by creating appropriate RPZ\. Each RPZ can have various rules associated with it\. The response of a recursive query is modified if it matches any of the RPZ rules\. The responses are first matched with the RPZ rules, and if there is a match, the rule defined at the RPZ level override is used\. The override depends on the order of RPZ\. The RPZs are prioritized in ascending order\. Ensure that the specified RPZ has policy override 'None\(GIVEN\)', so that rule defined at RPZ level override is used\. This action uses a multistep approach to block the domain\:<ul><li>Check if RPZ exists with policy override 'None\(GIVEN\)'\. If not, action will fail\.</li><li>Add the RPZ rule 'Block Domain Name \(No Such Domain\)' with the specified domain\. If another RPZ rule with a specified domain already exists with other than \(No Such Domain\) policy, the action will fail\.</li></ul>Default value for <b>network\_view</b> is 'default'\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to block | string |  `domain`  `url` 
**rp\_zone** |  required  | FQDN of response policy zone | string |  `infoblox rpz` 
**network\_view** |  optional  | Network view | string |  `infoblox view` 
**comment** |  optional  | Comment \(maximum 256 characters\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.parameter\.network\_view | string |  `infoblox view` 
action\_result\.parameter\.rp\_zone | string |  `infoblox rpz` 
action\_result\.data\.\*\.reference\_link | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list rpz'
List details of Response Policy Zones

Type: **investigate**  
Read only: **True**

Default value for <b>network\_view</b> is 'default'\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**network\_view** |  optional  | Network view | string |  `infoblox view` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.network\_view | string |  `infoblox view` 
action\_result\.data\.\*\.\_ref | string | 
action\_result\.data\.\*\.comment | string | 
action\_result\.data\.\*\.disable | boolean | 
action\_result\.data\.\*\.fqdn | string |  `infoblox rpz` 
action\_result\.data\.\*\.network\_view | string |  `infoblox view` 
action\_result\.data\.\*\.ns\_group | string | 
action\_result\.data\.\*\.primary\_type | string | 
action\_result\.data\.\*\.rpz\_last\_updated\_time | string | 
action\_result\.data\.\*\.rpz\_policy | string | 
action\_result\.data\.\*\.rpz\_priority | numeric | 
action\_result\.data\.\*\.rpz\_severity | string | 
action\_result\.data\.\*\.rpz\_type | string | 
action\_result\.data\.\*\.substitute\_name | string | 
action\_result\.summary\.total\_response\_policy\_zones | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list hosts'
List available hosts

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.\_ref | string | 
action\_result\.data\.\*\.discovered\_data\.first\_discovered | numeric | 
action\_result\.data\.\*\.discovered\_data\.last\_discovered | numeric | 
action\_result\.data\.\*\.discovered\_data\.mac\_address | string |  `mac address` 
action\_result\.data\.\*\.discovered\_data\.os | string | 
action\_result\.data\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.name | string |  `host name` 
action\_result\.data\.\*\.view | string |  `infoblox view` 
action\_result\.data\.\*\.zone | string | 
action\_result\.summary\.total\_hosts | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 