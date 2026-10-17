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
"""Constants shared by the Infoblox app and its actions."""

# Shared action behavior and messages.
INFOBLOX_JSON_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
INFOBLOX_HOST_INFO_UNAVAILABLE = (
    "The host might not be available or could be using statically configured IP and belongs to non-default network view"
)
INFOBLOX_RP_ZONE_POLICY_RULE_ERROR = "Policy rule of the Response Policy Zone must be 'GIVEN'.\nFound: '{rule_name}'"
INFOBLOX_RP_ZONE_NOT_EXISTS = "Response Policy Zone with FQDN: '{fqdn_name}' does not exist"
INFOBLOX_VALIDATE_MESSAGE = "Validating Response Policy Zone name and RPZ rule name"
INFOBLOX_NETWORK_VIEW_INFO_UNAVAILABLE = "Network View information unavailable"
INFOBLOX_LIST_RPZ_NON_DEF_MESSAGE = "This action gets the data from default network view only"

# Action result keys and messages.
INFOBLOX_JSON_ADDRESS = "address"
INFOBLOX_JSON_BINDING_STATE = "binding_state"
INFOBLOX_PARAM_CANONICAL = "canonical"
INFOBLOX_JSON_COMMENT = "comment"
INFOBLOX_JSON_DISCOVERED_DATA = "discovered_data"
INFOBLOX_PARAM_FQDN = "fqdn"
INFOBLOX_JSON_HARDWARE = "hardware"
INFOBLOX_JSON_IP = "ip"
INFOBLOX_JSON_A_IP = "ipv4addr"
INFOBLOX_JSON_AAAA_IP = "ipv6addr"
INFOBLOX_JSON_MAC_ADDRESS = "mac_address"
INFOBLOX_JSON_RECORD_NAME = "name"
INFOBLOX_JSON_NETWORK = "network"
INFOBLOX_JSON_NETWORK_VIEW = "network_view"
INFOBLOX_JSON_NEVER_ENDS = "never_ends"
INFOBLOX_JSON_OS = "os"
INFOBLOX_JSON_PROTOCOL = "protocol"
INFOBLOX_REFERENCE_LINK = "reference_link"
INFOBLOX_JSON_RP_ZONE = "rp_zone"
INFOBLOX_RPZ_POLICY = "rpz_policy"
INFOBLOX_LAST_UPDATED_TIME = "rpz_last_updated_time"
INFOBLOX_JSON_STARTS = "starts"
INFOBLOX_JSON_ENDS = "ends"
INFOBLOX_JSON_CLTT = "cltt"
INFOBLOX_JSON_IS_STATIC_IP = "is_static_ip"
INFOBLOX_JSON_ERROR_MESSAGE = "error_message"
INFOBLOX_JSON_CONTENT_TYPE = "Content-Type"
INFOBLOX_JSON_NEXT_PAGE_ID = "next_page_id"
INFOBLOX_RESOURCE_NOT_FOUND = "resource_not_found"
INFOBLOX_JSON_RESULT = "result"
INFOBLOX_JSON_TEXT = "text"
INFOBLOX_TOTAL_HOSTS = "total_hosts"
INFOBLOX_TOTAL_RESPONSE_POLICY_ZONES = "total_response_policy_zones"
INFOBLOX_PARAM_VIEW = "view"
INFOBLOX_PARAM_ZONE = "zone"
INFOBLOX_JSON_SUCCESS = "success"
INFOBLOX_JSON_MESSAGE = "message"
INFOBLOX_JSON_REF = "_ref"

INFOBLOX_DOMAIN_ALREADY_BLOCKED = "Domain already blocked"
INFOBLOX_DOMAIN_ALREADY_UNBLOCKED = "Domain already unblocked"
INFOBLOX_BLOCK_DOMAIN_SUCCESS = "Domain blocked successfully"
INFOBLOX_DOMAIN_UNBLOCK_SUCCESS = "Domain unblocked successfully"
INFOBLOX_DOMAIN_EXISTS_NOT_IN_BLOCKED_STATE = (
    "RPZ rule for specified domain already exists, But it is not of type 'Block Domain Name (No Such Domain) Rule'"
)
INFOBLOX_DOMAIN_NOT_IN_BLOCKED_STATE = "RPZ rule for specified domain is not of type 'Block Domain Name (No Such Domain) Rule'"
INFOBLOX_INVALID_DOMAIN_PARAMETER = "Please provide a valid 'domain' parameter. {}"
INFOBLOX_IP_ALREADY_BLOCKED = "IP/CIDR already blocked"
INFOBLOX_IP_ALREADY_UNBLOCKED = "IP/CIDR already unblocked"
INFOBLOX_BLOCK_IP_SUCCESS = "IP/CIDR blocked successfully"
INFOBLOX_IP_UNBLOCK_SUCCESS = "IP/CIDR unblocked successfully"
INFOBLOX_IP_VALIDATION_FAILED = "parameter 'ip' validation failed"
INFOBLOX_IP_EXISTS_NOT_IN_BLOCKED_STATE = (
    "RPZ rule for specified IP already exists, But it is not of type 'Block IP Address (No Such Domain) Rule'"
)
INFOBLOX_IP_NOT_IN_BLOCKED_STATE = "RPZ rule for specified IP is not of type 'Block IP Address (No Such Domain) Rule'"
INFOBLOX_ERROR_SERVER_CONNECTION = "Connection failed"
INFOBLOX_REST_RESP_OTHER_ERROR_MESSAGE = "Unknown error occurred"
INFOBLOX_ERROR_MESSAGE_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or the action parameters."
INFOBLOX_ERROR_FROM_SERVER = "API failed\nStatus code: {status}\nDetail: {detail}"
INFOBLOX_ERROR_JSON_PARSE = "Unable to parse the fields parameter into a dictionary.\nResponse text - {raw_text}"
INFOBLOX_PAGINATION_MAX_ERROR_FORMAT = "Stopped pagination after the maximum of {max_pages} pages"
INFOBLOX_PAGINATION_REPEAT_ERROR = "Stopped pagination because the server repeated next_page_id"
INFOBLOX_PAGE_COUNT = "Making paged request... #{0}"

INFOBLOX_TEST_CONN_FAILED = "Connectivity test failed"
INFOBLOX_TEST_CONN_SUCCESS = "Connectivity test succeeded"
INFOBLOX_TEST_ENDPOINT = "/?_schema"

# WAPI configuration.
INFOBLOX_BASE_ENDPOINT = "/wapi/v2.3.1"
INFOBLOX_NETWORK_VIEW_DEFAULT = "default"
DEFAULT_REQUEST_TIMEOUT = 30
INFOBLOX_PAGE_SIZE = 1000
INFOBLOX_MAX_PAGE_COUNT = 100

# WAPI endpoints.
INFOBLOX_NETWORK_VIEW = "/networkview"
INFOBLOX_NETWORK_ENDPOINT = "/network"
INFOBLOX_LEASE = "/lease"
INFOBLOX_LOGOUT = "/logout"
INFOBLOX_RP_ZONE_DETAILS_ENDPOINT = "/zone_rp"
INFOBLOX_DOMAIN_ENDPOINT = "/record:rpz:cname"
INFOBLOX_IP_ENDPOINT = "/record:rpz:cname:ipaddress"
INFOBLOX_RECORDS_IPv4_ENDPOINT = "/record:a"
INFOBLOX_RECORDS_IPv6_ENDPOINT = "/record:aaaa"

# WAPI fields and protocol labels.
INFOBLOX_JSON_CLIENT_HOSTNAME = "client_hostname"
INFOBLOX_JSON_CONTEXT_NAME_SEARCH = "name~"
INFOBLOX_PROTOCOL_IPV4 = "IPV4"
INFOBLOX_PROTOCOL_IPV6 = "IPV6"
INFOBLOX_RECORD_A_RETURN_FIELDS = "ipv4addr,name,view,zone,discovered_data"
INFOBLOX_RECORD_AAAA_RETURN_FIELDS = "ipv6addr,name,view,zone,discovered_data"
INFOBLOX_LEASE_RETURN_FIELDS = (
    "binding_state,starts,ends,address,billing_class,client_hostname,tsfp,tstp,uid,"
    "remote_id,username,variable,cltt,hardware,network,network_view,option,protocol,"
    "served_by,server_host_name,billing_class,ipv6_duid,ipv6_iaid,ipv6_preferred_lifetime,"
    "ipv6_prefix_bits,is_invalid_mac,never_ends,never_starts,next_binding_state,on_commit,"
    "on_expiry,on_release"
)
INFOBLOX_HOST_RETURN_FIELDS = "ipv4addr,name,view,zone"
INFOBLOX_HOST_IPV6_RETURN_FIELDS = "ipv6addr,name,view,zone"

# WAPI query parameter names.
INFOBLOX_JSON_RETURN_FIELDS = "_return_fields"
INFOBLOX_JSON_PAGING = "_paging"
INFOBLOX_JSON_RETURN_AS_OBJECT = "_return_as_object"
INFOBLOX_JSON_MAX_RESULTS = "_max_results"
INFOBLOX_JSON_PAGE_ID = "_page_id"

# API response and RPZ metadata.
INFOBLOX_REST_RESP_BAD_REQUEST = 400
INFOBLOX_REST_RESP_BAD_REQUEST_MESSAGE = "Bad Request"
INFOBLOX_REST_RESP_UNAUTHORIZED = 401
INFOBLOX_REST_RESP_UNAUTHORIZED_MESSAGE = "Unauthorized"
INFOBLOX_REST_RESP_FORBIDDEN = 403
INFOBLOX_REST_RESP_FORBIDDEN_MESSAGE = "Forbidden"
INFOBLOX_REST_RESP_NOT_FOUND = 404
INFOBLOX_REST_RESP_NOT_FOUND_MESSAGE = "Not found"
INFOBLOX_REST_RESP_METHOD_NOT_ALLOWED = 405
INFOBLOX_REST_RESP_METHOD_NOT_ALLOWED_MESSAGE = "Method not allowed"
INFOBLOX_REST_RESP_INTERNAL_SERVER_ERROR = 500
INFOBLOX_REST_RESP_INTERNAL_SERVER_ERROR_MESSAGE = "Internal server error"
INFOBLOX_REST_RESPONSE_MESSAGES = {
    INFOBLOX_REST_RESP_BAD_REQUEST: INFOBLOX_REST_RESP_BAD_REQUEST_MESSAGE,
    INFOBLOX_REST_RESP_UNAUTHORIZED: INFOBLOX_REST_RESP_UNAUTHORIZED_MESSAGE,
    INFOBLOX_REST_RESP_FORBIDDEN: INFOBLOX_REST_RESP_FORBIDDEN_MESSAGE,
    INFOBLOX_REST_RESP_NOT_FOUND: INFOBLOX_REST_RESP_NOT_FOUND_MESSAGE,
    INFOBLOX_REST_RESP_METHOD_NOT_ALLOWED: INFOBLOX_REST_RESP_METHOD_NOT_ALLOWED_MESSAGE,
    INFOBLOX_REST_RESP_INTERNAL_SERVER_ERROR: INFOBLOX_REST_RESP_INTERNAL_SERVER_ERROR_MESSAGE,
}
INFOBLOX_LIST_RP_ZONE_PARAMS = (
    "rpz_policy,fqdn,rpz_severity,disable,rpz_type,primary_type,ns_group,network_view,rpz_priority,rpz_last_updated_time,comment,substitute_name"
)
