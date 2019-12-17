# File: infobloxddi_consts.py
# Copyright (c) 2017-2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

INFOBLOX_CONFIG_USERNAME = "username"
INFOBLOX_CONFIG_PASSWORD = "password"
INFOBLOX_CONFIG_URL = "url"
INFOBLOX_CONFIG_VERIFY_SERVER_CERT = "verify_server_cert"
INFOBLOX_JSON_IP_HOSTNAME = "ip_hostname"
INFOBLOX_JSON_NETWORK_VIEW = "network_view"
INFOBLOX_JSON_RETURN_FIELDS = "_return_fields"
INFOBLOX_JSON_ADDRESS = "address"
INFOBLOX_JSON_CLIENT_HOSTNAME = "client_hostname"
INFOBLOX_JSON_CLTT = "cltt"
INFOBLOX_JSON_DOMAIN = "domain"
INFOBLOX_JSON_IP = "ip"
INFOBLOX_JSON_A_IP = "ipv4addr"
INFOBLOX_JSON_AAAA_IP = "ipv6addr"
INFOBLOX_JSON_RECORD_NAME = "name"
INFOBLOX_JSON_RP_ZONE = "rp_zone"
INFOBLOX_JSON_COMMENT = "comment"
INFOBLOX_JSON_STARTS = "starts"
INFOBLOX_JSON_ENDS = "ends"
INFOBLOX_JSON_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
INFOBLOX_JSON_HARDWARE = "hardware"
INFOBLOX_JSON_OS = "os"
INFOBLOX_JSON_PROTOCOL = "protocol"
INFOBLOX_JSON_CONTENT_TYPE = "Content-Type"
INFOBLOX_REST_RESP_SUCCESS = 200
INFOBLOX_REST_RESP_CREATE_SUCCESS = 201
INFOBLOX_REST_RESP_BAD_REQUEST = 400
INFOBLOX_REST_RESP_BAD_REQUEST_MSG = "Bad Request"
INFOBLOX_REST_RESP_UNAUTHORIZED = 401
INFOBLOX_REST_RESP_UNAUTHORIZED_MSG = "Unauthorized"
INFOBLOX_REST_RESP_FORBIDDEN = 403
INFOBLOX_REST_RESP_FORBIDDEN_MSG = "Forbidden"
INFOBLOX_REST_RESP_NOT_FOUND = 404
INFOBLOX_REST_RESP_NOT_FOUND_MSG = "Not found"
INFOBLOX_REST_RESP_METHOD_NOT_ALLOWED = 405
INFOBLOX_REST_RESP_METHOD_NOT_ALLOWED_MSG = "Method not allowed"
INFOBLOX_REST_RESP_INTERNAL_SERVER_ERROR = 500
INFOBLOX_REST_RESP_INTERNAL_SERVER_ERROR_MSG = "Internal server error"
INFOBLOX_ERR_API_UNSUPPORTED_METHOD = "Unsupported method {method}"
INFOBLOX_EXCEPTION_OCCURRED = "Exception occurred"
INFOBLOX_PARAM_VIEW = "view"
INFOBLOX_PARAM_CANONICAL = "canonical"
INFOBLOX_PARAM_FQDN = "fqdn"
INFOBLOX_PARAM_ZONE = "zone"
INFOBLOX_NETWORK_VIEW_DEFAULT = "default"
INFOBLOX_RPZ_RULE_NAME = "name"
INFOBLOX_RPZ_POLICY = "rpz_policy"
INFOBLOX_LAST_UPDATED_TIME = "rpz_last_updated_time"
INFOBLOX_BASE_ENDPOINT = "/wapi/v2.3.1"
INFOBLOX_NETWORK_VIEW = "/networkview"
INFOBLOX_LEASE = "/lease"
INFOBLOX_LOGOUT = "/logout"
INFOBLOX_DOMAIN_ENDPOINT = "/record:rpz:cname"
INFOBLOX_IP_ENDPOINT = "/record:rpz:cname:ipaddress"
INFOBLOX_RP_ZONE_DETAILS_ENDPOINT = "/zone_rp"
INFOBLOX_RECORDS_IPv4_ENDPOINT = "/record:a"
INFOBLOX_RECORDS_IPv6_ENDPOINT = "/record:aaaa"
INFOBLOX_LEASE_RETURN_FIELDS = "binding_state,starts,ends,address,billing_class,client_hostname,tsfp,tstp,uid," \
                               "remote_id,username,variable,cltt,hardware,network,network_view,option,protocol," \
                               "served_by,server_host_name,billing_class,ipv6_duid,ipv6_iaid,ipv6_preferred_lifetime," \
                               "ipv6_prefix_bits,is_invalid_mac,never_ends,never_starts,next_binding_state,on_commit," \
                               "on_expiry,on_release"
INFOBLOX_RECORD_A_RETURN_FIELDS = "ipv4addr,name,view,zone,discovered_data"
INFOBLOX_RECORD_AAAA_RETURN_FIELDS = "ipv6addr,name,view,zone,discovered_data"
INFOBLOX_ERR_SERVER_CONNECTION = "Connection failed"
INFOBLOX_ERR_FROM_SERVER = "API failed\nStatus code: {status}\nDetail: {detail}"
INFOBLOX_ERR_JSON_PARSE = "Unable to parse the fields parameter into a dictionary.\nResponse text - {raw_text}"
INFOBLOX_REST_RESP_OTHER_ERROR_MSG = "Unknown error occurred"
INFOBLOX_TEST_CONNECTIVITY_MSG = "Logging into device"
INFOBLOX_TEST_CONN_FAIL = "Connectivity test failed"
INFOBLOX_TEST_CONN_SUCC = "Connectivity test succeeded"
INFOBLOX_TEST_ENDPOINT_MSG = "Querying endpoint '{endpoint}' to validate credentials"
INFOBLOX_RESPONSE_DATA = "response_data"
INFOBLOX_RESOURCE_NOT_FOUND = "resource_not_found"
INFOBLOX_NETWORK_VIEW_INFO_UNAVAILABLE = "Network View information unavailable"
INFOBLOX_HOST_INFO_UNAVAILABLE = "The host might not be available or could be using statically configured IP and \
belongs to non-default network view"
INFOBLOX_LIST_RP_ZONE_PARAMS = "rpz_policy,fqdn,rpz_severity,disable,rpz_type,primary_type,ns_group,network_view,\
rpz_priority,rpz_last_updated_time,comment,substitute_name"
INFOBLOX_BLOCK_POLICY_RULE = "GIVEN"
INFOBLOX_LIST_RP_ZONE_ERROR = "Error while getting Response Policy Zone details"
INFOBLOX_LIST_HOSTS_ERROR = "Error while getting list of hosts"
INFOBLOX_RP_ZONE_POLICY_RULE_ERROR = "Policy rule of the Response Policy Zone must be 'GIVEN'.\nFound: '{rule_name}'"
INFOBLOX_RP_ZONE_NOT_EXISTS = "Response Policy Zone with FQDN: '{fqdn_name}' does not exist"
INFOBLOX_VALIDATE_MESSAGE = "Validating Response Policy Zone name and RPZ rule name"
INFOBLOX_DOMAIN_ALREADY_BLOCKED = "Domain already blocked"
INFOBLOX_IP_ALREADY_BLOCKED = "IP/CIDR already blocked"
INFOBLOX_BLOCK_DOMAIN_SUCCESS = "Domain blocked successfully"
INFOBLOX_BLOCK_IP_SUCCESS = "IP/CIDR blocked successfully"
INFOBLOX_IP_VALIDATION_FAILED = "parameter 'ip' validation failed"
INFOBLOX_DOMAIN_NOT_IN_BLOCKED_STATE = "RPZ rule for specified domain is not of type 'Block Domain Name \
(No Such Domain) Rule'"
INFOBLOX_IP_NOT_IN_BLOCKED_STATE = "RPZ rule for specified IP is not of type 'Block IP Address \
(No Such Domain) Rule'"
INFOBLOX_DOMAIN_EXISTS_NOT_IN_BLOCKED_STATE = "RPZ rule for specified domain already exists, But it is not of type \
'Block Domain Name (No Such Domain) Rule'"
INFOBLOX_IP_EXISTS_NOT_IN_BLOCKED_STATE = "RPZ rule for specified IP already exists, But it is not of type \
'Block IP Address (No Such Domain) Rule'"
INFOBLOX_IP_ALREADY_UNBLOCKED = "IP/CIDR already unblocked"
INFOBLOX_IP_UNBLOCK_SUCCESS = "IP/CIDR unblocked successfully"
INFOBLOX_DOMAIN_ALREADY_UNBLOCKED = "Domain already unblocked"
INFOBLOX_DOMAIN_UNBLOCK_SUCCESS = "Domain unblocked successfully"
INFOBLOX_REFERENCE_LINK = "reference_link"
INFOBLOX_TOTAL_RESPONSE_POLICY_ZONES = "total_response_policy_zones"
INFOBLOX_TOTAL_HOSTS = "total_hosts"
INFOBLOX_LIST_RPZ_NON_DEF_MSG = "This action gets the data from default network view only"
