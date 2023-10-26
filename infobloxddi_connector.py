# File: infobloxddi_connector.py
#
# Copyright (c) 2017-2023 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Standard library imports
import ipaddress
import json
import socket
import sys
import time

# Phantom imports
import phantom.app as phantom
import requests
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

# Local imports
import infobloxddi_consts as consts

# Dictionary that maps each error code with its corresponding message
ERROR_RESPONSE_DICT = {
    consts.INFOBLOX_REST_RESP_BAD_REQUEST: consts.INFOBLOX_REST_RESP_BAD_REQUEST_MESSAGE,
    consts.INFOBLOX_REST_RESP_UNAUTHORIZED: consts.INFOBLOX_REST_RESP_UNAUTHORIZED_MESSAGE,
    consts.INFOBLOX_REST_RESP_FORBIDDEN: consts.INFOBLOX_REST_RESP_FORBIDDEN_MESSAGE,
    consts.INFOBLOX_REST_RESP_NOT_FOUND: consts.INFOBLOX_REST_RESP_NOT_FOUND_MESSAGE,
    consts.INFOBLOX_REST_RESP_METHOD_NOT_ALLOWED: consts.INFOBLOX_REST_RESP_METHOD_NOT_ALLOWED_MESSAGE,
    consts.INFOBLOX_REST_RESP_INTERNAL_SERVER_ERROR: consts.INFOBLOX_REST_RESP_INTERNAL_SERVER_ERROR_MESSAGE
}

# List containing HTTP codes to be considered as success
SUCCESS_RESPONSE_CODES = [consts.INFOBLOX_REST_RESP_SUCCESS, consts.INFOBLOX_REST_RESP_CREATE_SUCCESS]


def _break_ip_address(cidr_ip_address):
    """ Function divides the input parameter into IP address and network mask.

    :param cidr_ip_address: IP address in format of IP/prefix_size
    :return: IP, prefix_size
    """

    if "/" in cidr_ip_address:
        ip_address, prefix_size = cidr_ip_address.split("/")
    else:
        ip_address = cidr_ip_address
        prefix_size = 0

    return ip_address, int(prefix_size)


def _is_ipv6(ip_address):
    """ Function that checks given address and return True if address is IPv6 address.

    :param ip_address: input parameter IP address
    :return: status (success/failure)
    """

    try:
        # Validating IPv6 address
        socket.inet_pton(socket.AF_INET6, ip_address)
    except socket.error:
        return False

    return True


class InfobloxddiConnector(BaseConnector):
    """ This is an AppConnector class that inherits the BaseConnector class. It implements various actions supported by
    Infoblox DDI and helper methods required to run the actions.
    """

    def __init__(self):

        # Calling the BaseConnector's init function
        super(InfobloxddiConnector, self).__init__()

        self._url = None
        self._api_username = None
        self._api_password = None
        self._verify_server_cert = False
        self._sess_obj = None
        self._state = None
        return

    def initialize(self):
        """ This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """

        config = self.get_config()
        self._state = self.load_state()

        # Initializing parameters required for connection
        self._url = config[consts.INFOBLOX_CONFIG_URL].strip("/")
        self._api_username = config[consts.INFOBLOX_CONFIG_USERNAME]
        self._api_password = config[consts.INFOBLOX_CONFIG_PASSWORD]
        self._verify_server_cert = config.get(consts.INFOBLOX_CONFIG_VERIFY_SERVER_CERT, False)

        # Custom validation for IP address
        self.set_validator(consts.INFOBLOX_JSON_IP, self._is_ip)

        # Initializing session object which would be used for subsequent API calls
        self._sess_obj = requests.session()

        return phantom.APP_SUCCESS

    def _get_error_message_from_exception(self, e):
        """Get an appropriate error message from the exception.

            :param e: Exception object
            :return: error message
            """
        error_code = None
        error_message = consts.INFOBLOX_ERROR_MESSAGE_UNAVAILABLE

        self.error_print("Error occurred.", e)
        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_message = e.args[1]
                elif len(e.args) == 1:
                    error_message = e.args[0]
        except Exception as e:
            self.error_print(
                f"Error occurred while fetching exception information. Details: {str(e)}")

        if not error_code:
            error_text = f"Error message: {error_message}"
        else:
            error_text = f"Error code: {error_code}. Error message: {error_message}"

        return error_text

    def _is_ip(self, cidr_ip_address):
        """ Function that checks given address and return True if address is valid IPv4/IPv6 address.

        :param cidr_ip_address: IP address
        :return: status (success/failure)
        """

        try:
            ip_address, net_mask = _break_ip_address(cidr_ip_address)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            self.debug_print("{}. {}".format(consts.INFOBLOX_IP_VALIDATION_FAILED, error_message))
            return False

        # Validate IP address
        if not (phantom.is_ip(ip_address) or _is_ipv6(ip_address)):
            self.debug_print(consts.INFOBLOX_IP_VALIDATION_FAILED)
            return False

        # Check if net mask is out of range
        if (":" in ip_address and net_mask not in range(0, 129)) or ("." in ip_address and net_mask not in range(0, 33)):
            self.debug_print(consts.INFOBLOX_IP_VALIDATION_FAILED)
            return False

        return True

    def _get_rp_zone_details(self, action_result, zone_filter_params):
        """ Helper function to get Response Policy Zone details.

        :param action_result: Object of ActionResult class
        :param zone_filter_params: Object containing RP zone details
        :return: status (success/failure) and (zone details or None)
        """

        if not zone_filter_params:
            zone_filter_params = dict()

        # Adding fields to be returned in the API response
        zone_filter_params.update({
            consts.INFOBLOX_JSON_RETURN_FIELDS: consts.INFOBLOX_LIST_RP_ZONE_PARAMS
        })

        # Getting rp_zone details
        rp_zone_details_status, rpz_zone_details = self._make_paged_rest_call(
            consts.INFOBLOX_RP_ZONE_DETAILS_ENDPOINT,
            action_result,
            params=zone_filter_params,
            method="get")

        # Something went wrong while getting rp_zone details
        if phantom.is_fail(rp_zone_details_status):
            self.debug_print(consts.INFOBLOX_LIST_RP_ZONE_ERROR)
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, rpz_zone_details

    def _validate_rp_zone(self, action_result, zone_details_param):
        """ Helper function to check if given rp_zone exists. If rp_zone exists, then function will return success if
        policy rule of the given rp_zone is None(GIVEN), else it will return failure.

        :param action_result: Object of ActionResult class
        :param zone_details_param: Object containing RP zone details
        :return: status (success/failure)
        """

        # Checking if given response policy zone exists
        rp_zone_details_status, rp_zone_details = self._get_rp_zone_details(action_result, zone_details_param)

        # Something went wrong while getting rp_zone details
        if phantom.is_fail(rp_zone_details_status):
            return action_result.get_status()

        # Provided response policy zone does not exist
        if not rp_zone_details:
            self.debug_print(consts.INFOBLOX_RP_ZONE_NOT_EXISTS.format(fqdn_name=zone_details_param[
                consts.INFOBLOX_PARAM_FQDN
            ]))
            # Set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, consts.INFOBLOX_RP_ZONE_NOT_EXISTS.format(
                fqdn_name=zone_details_param[consts.INFOBLOX_PARAM_FQDN]
            ))

        rp_zone_details = rp_zone_details[0]

        # Checking if Policy Rule of provided rp_zone is 'GIVEN'
        if rp_zone_details[consts.INFOBLOX_RPZ_POLICY] != consts.INFOBLOX_BLOCK_POLICY_RULE:
            self.debug_print(consts.INFOBLOX_RP_ZONE_POLICY_RULE_ERROR.format(rule_name=rp_zone_details[
                consts.INFOBLOX_RPZ_POLICY
            ]))
            # Set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, consts.INFOBLOX_RP_ZONE_POLICY_RULE_ERROR.format(
                rule_name=rp_zone_details[consts.INFOBLOX_RPZ_POLICY]
            ))

        return phantom.APP_SUCCESS

    def _make_rest_call(self, endpoint, action_result, params=None, data=None, method="post", timeout=None):
        """ Function that makes the REST call to the device. It's a generic function that can be called from various
        action handlers.

        :param endpoint: REST endpoint that appends to the service address
        :param action_result: Object of ActionResult class
        :param params: request parameters if method is GET
        :param data: request body if method is POST
        :param method: GET/POST/PUT/DELETE (Default method will be "POST")
        :param timeout: request timeout in seconds
        :return: status (success/failure) (along with appropriate message), response obtained by making an API call
        """

        response_data = None
        response_json_data = None

        # To provide authentication
        credential_data = (self._api_username, self._api_password)

        try:
            request_func = getattr(self._sess_obj, method)
        except AttributeError:
            self.debug_print(consts.INFOBLOX_ERROR_API_UNSUPPORTED_METHOD.format(method=method))
            # Set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, consts.INFOBLOX_ERROR_API_UNSUPPORTED_METHOD.format(
                method=method)), response_data
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            self.debug_print("{}. {}".format(consts.INFOBLOX_EXCEPTION_OCCURRED, error_message))
            # Set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, "{}. {}".format(consts.INFOBLOX_EXCEPTION_OCCURRED, error_message)), response_data

        # Make the call
        try:
            if timeout is not None:
                request_obj = request_func("{}{}{}".format(self._url, consts.INFOBLOX_BASE_ENDPOINT, endpoint),
                                           auth=credential_data, params=params, data=data, timeout=timeout,
                                           verify=self._verify_server_cert)
            else:
                request_obj = request_func("{}{}{}".format(self._url, consts.INFOBLOX_BASE_ENDPOINT, endpoint),
                                           auth=credential_data, params=params, data=data,
                                           verify=self._verify_server_cert)

            # store the r_text in debug data, it will get dumped in the logs if an error occurs
            if hasattr(action_result, 'add_debug_data'):
                if request_obj is not None:
                    action_result.add_debug_data({'r_status_code': request_obj.status_code})
                    action_result.add_debug_data({'r_text': request_obj.text})
                    action_result.add_debug_data({'r_headers': request_obj.headers})
                else:
                    action_result.add_debug_data({'r_text': 'r is None'})

        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            self.debug_print("{}. {}".format(consts.INFOBLOX_ERROR_SERVER_CONNECTION, error_message))
            # Set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR,
                                            "{}. {}".format(consts.INFOBLOX_ERROR_SERVER_CONNECTION, error_message)), response_data

        # Handling the 404 status code for list_rpz action
        if self.get_action_identifier() == "list_rpz" and \
                request_obj.status_code == consts.INFOBLOX_REST_RESP_NOT_FOUND:
            response_data = {
                consts.INFOBLOX_RESOURCE_NOT_FOUND: True
            }
            try:
                response_data["error_message"] = json.loads(request_obj.text).get("text")
            except Exception:
                pass
            return phantom.APP_SUCCESS, response_data

        if request_obj.status_code in ERROR_RESPONSE_DICT:
            message = ERROR_RESPONSE_DICT[request_obj.status_code]

            try:
                if isinstance(request_obj.json(), dict):
                    message = request_obj.json().get("text", message)
            except Exception:
                pass

            self.debug_print(consts.INFOBLOX_ERROR_FROM_SERVER.format(status=request_obj.status_code, detail=message))

            # Set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(
                phantom.APP_ERROR,
                consts.INFOBLOX_ERROR_FROM_SERVER.format(status=request_obj.status_code, detail=message)
            ), response_data

        try:
            content_type = request_obj.headers[consts.INFOBLOX_JSON_CONTENT_TYPE]
            if content_type.find("json") != -1:
                response_json_data = request_obj.json()

        except Exception as e:
            # request_obj.text is guaranteed to be NON None, it will be empty, but not None
            message = consts.INFOBLOX_ERROR_JSON_PARSE.format(raw_text=request_obj.text)
            error_message = self._get_error_message_from_exception(e)
            self.debug_print("{}. {}".formate(message, error_message))
            # Set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, "{}. {}".formate(message, error_message)), response_data

        if request_obj.status_code in SUCCESS_RESPONSE_CODES:
            response_data = {
                consts.INFOBLOX_RESPONSE_DATA: response_json_data,
                consts.INFOBLOX_JSON_CONTENT_TYPE: content_type
            }

            return phantom.APP_SUCCESS, response_data

        # If response code is unknown
        self.debug_print(consts.INFOBLOX_ERROR_FROM_SERVER.format(status=request_obj.status_code,
                                                                detail=consts.INFOBLOX_REST_RESP_OTHER_ERROR_MESSAGE))
        # All other response codes from REST call
        # Set the action_result status to error, the handler function will most probably return as is
        return action_result.set_status(
            phantom.APP_ERROR,
            consts.INFOBLOX_ERROR_FROM_SERVER.format(status=request_obj.status_code, detail=consts.INFOBLOX_REST_RESP_OTHER_ERROR_MESSAGE)
        ), response_data

    def _make_paged_rest_call(self, endpoint, action_result, params=None, **rest_call_options):
        """ Function used to make rest call requests in a paged fashion.
        This will alleviate errors with getting >1000 results from Infoblox.

        First make the main call with the search parameters.
        Then keep making the next rest call with the "next_page_id", if it is returned.

        :param endpoint: REST endpoint that appends to the service address
        :param action_result: Object of ActionResult class
        :param params: request parameters if method is GET
        :param rest_call_options: additional options for _make_rest_call
        :return: status (success/failure) (along with appropriate message), response obtained by making an API call
        """
        page_count = 1
        self.debug_print(consts.INFOBLOX_PAGE_COUNT.format(page_count))

        if not params:
            params = {}
        params[consts.INFOBLOX_JSON_PAGING] = 1
        params[consts.INFOBLOX_JSON_RETURN_AS_OBJECT] = 1
        params[consts.INFOBLOX_JSON_MAX_RESULTS] = 1000

        status, response = self._make_rest_call(endpoint, action_result, params, **rest_call_options)

        if phantom.is_fail(status):
            return action_result.get_status(), None

        if response.get(consts.INFOBLOX_RESOURCE_NOT_FOUND):
            return phantom.APP_SUCCESS, response

        response = response.get(consts.INFOBLOX_RESPONSE_DATA, {})

        combined_response = response.get('result', [])
        paged_params = {
            consts.INFOBLOX_JSON_PAGE_ID: response.get('next_page_id', None),
            consts.INFOBLOX_JSON_PAGING: 1,
            consts.INFOBLOX_JSON_RETURN_AS_OBJECT: 1
        }

        while paged_params.get(consts.INFOBLOX_JSON_PAGE_ID) is not None:

            page_count += 1
            self.debug_print(consts.INFOBLOX_PAGE_COUNT.format(page_count))

            status, response = self._make_rest_call(endpoint, action_result, paged_params, **rest_call_options)

            if phantom.is_fail(status):
                return action_result.get_status(), combined_response

            response = response.get(consts.INFOBLOX_RESPONSE_DATA, {})

            combined_response.extend(response.get('result', []))
            paged_params[consts.INFOBLOX_JSON_PAGE_ID] = response.get('next_page_id', None)

        return phantom.APP_SUCCESS, combined_response

    def _logout(self):
        """ Function used to logout from Infoblox Grid Manager. Called from finalize method at the end of each action.

        :return: status (success/failure)
        """

        # Only initializing action_result for REST calls, not adding it to BaseConnector
        action_result = ActionResult()

        status, response = self._make_rest_call(consts.INFOBLOX_LOGOUT, action_result)

        # Something went wrong
        if phantom.is_fail(status):
            return action_result.get_status()

        return phantom.APP_SUCCESS

    def _test_asset_connectivity(self, param):
        """ This function tests the connectivity of an asset with given credentials.

        :param param: dictionary of input parameters
        :return: status (success/failure)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress(consts.INFOBLOX_TEST_CONNECTIVITY_MESSAGE)
        self.save_progress("Configured URL: {url}".format(url=self._url))

        self.save_progress(consts.INFOBLOX_TEST_ENDPOINT_MESSAGE.format(endpoint='/?_schema'))

        # Querying endpoint to check connection to device
        status, response = self._make_rest_call('/?_schema', action_result, method="get", timeout=30)

        if phantom.is_fail(status):
            self.save_progress(action_result.get_message())
            return action_result.set_status(phantom.APP_ERROR, consts.INFOBLOX_TEST_CONN_FAILED)

        self.save_progress(consts.INFOBLOX_TEST_CONN_SUCCESS)
        return action_result.set_status(phantom.APP_SUCCESS, consts.INFOBLOX_TEST_CONN_SUCCESS)

    def _get_network_info(self, param):
        """ To get details about DHCP network(s)

        :param param: dictionary of input parameter
        :return: status (success/failure)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param.get('ip')  # IP or CIDR network format
        network_view = param.get('network_view')  # Infoblox network view

        search_ip = None  # Only used if the input ip is not in CIDR format
        params = {}

        # REST API allows for the user to search by the network (if in CIDR notation)
        # Otherwise, we will need to process all results and return filtered output after the REST call
        # If no IP is given, return all
        if ip and self._is_ip(ip):
            if '/' in ip:  # CIDR Network, send ip to REST API call to search
                params[consts.INFOBLOX_JSON_NETWORK] = ip

            else:  # Set search IP to use after the REST call if the IP is just an IP
                # search_ip needs to be unicode in order to be used by ipaddress library
                search_ip = ip

        if network_view:
            params[consts.INFOBLOX_JSON_NETWORK_VIEW] = network_view

        status, response = self._make_paged_rest_call(consts.INFOBLOX_NETWORK_ENDPOINT, action_result, params, method='get')

        if phantom.is_fail(status):
            return action_result.get_status()

        for network_info in response:
            if search_ip:
                # Filter results of results for networks that match the provided IP
                if ipaddress.ip_address(search_ip) in ipaddress.ip_network(network_info.get('network')):
                    action_result.add_data(network_info)
            else:
                # Return all results
                action_result.add_data(network_info)

        action_result.update_summary({'number_of_matching_networks': action_result.get_data_size()})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_system_info(self, param):
        """ To get information about host, i.e. host's state is Free/Active/Static/Expired/Released/Abandoned/Backup/
        Offered/Declined/Reset.

        :param param: dictionary of input parameter
        :return: status (success/failure)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Default fields to return
        params = {
            consts.INFOBLOX_JSON_RETURN_FIELDS: consts.INFOBLOX_LEASE_RETURN_FIELDS
        }

        # Mandatory parameters
        ip_hostname = param[consts.INFOBLOX_JSON_IP_HOSTNAME]

        # Validate ip_hostname is valid IP address, if not, considering it hostname
        if phantom.is_ip(ip_hostname) or _is_ipv6(ip_hostname):
            params[consts.INFOBLOX_JSON_ADDRESS] = ip_hostname
        else:
            params[consts.INFOBLOX_JSON_CLIENT_HOSTNAME] = ip_hostname

        # Optional parameter
        params[consts.INFOBLOX_JSON_NETWORK_VIEW] = param.get(consts.INFOBLOX_JSON_NETWORK_VIEW,
                                                              consts.INFOBLOX_NETWORK_VIEW_DEFAULT)

        # Make call to get host information
        status, response = self._make_rest_call(consts.INFOBLOX_LEASE, action_result, params=params, method="get")
        # Something went wrong
        if phantom.is_fail(status):
            return action_result.get_status()

        lease_response_list = response[consts.INFOBLOX_RESPONSE_DATA]

        host_response_list = None
        # Fetching the details of host from records:a/aaaa if network view is default
        if param.get(consts.INFOBLOX_JSON_NETWORK_VIEW,
                     consts.INFOBLOX_NETWORK_VIEW_DEFAULT) == consts.INFOBLOX_NETWORK_VIEW_DEFAULT:
            # Invoking record:a for ipv4
            if phantom.is_ip(ip_hostname):
                record_a_params = {
                    consts.INFOBLOX_JSON_RETURN_FIELDS: consts.INFOBLOX_RECORD_A_RETURN_FIELDS,
                    consts.INFOBLOX_JSON_A_IP: ip_hostname,
                    consts.INFOBLOX_PARAM_VIEW: consts.INFOBLOX_NETWORK_VIEW_DEFAULT
                }

                # Make call to get lease information
                host_status, host_response = self._make_rest_call(consts.INFOBLOX_RECORDS_IPv4_ENDPOINT, action_result,
                                                                  params=record_a_params, method="get")

                # Something went wrong
                if phantom.is_fail(host_status):
                    return action_result.get_status()

            # Invoking record:a if ipv6
            elif _is_ipv6(ip_hostname):
                record_aaaa_params = {
                    consts.INFOBLOX_JSON_RETURN_FIELDS: consts.INFOBLOX_RECORD_AAAA_RETURN_FIELDS,
                    consts.INFOBLOX_JSON_AAAA_IP: ip_hostname,
                    consts.INFOBLOX_PARAM_VIEW: consts.INFOBLOX_NETWORK_VIEW_DEFAULT
                }

                # Make call to get lease information
                host_status, host_response = self._make_rest_call(consts.INFOBLOX_RECORDS_IPv6_ENDPOINT, action_result,
                                                                  params=record_aaaa_params, method="get")

                # Something went wrong
                if phantom.is_fail(host_status):
                    return action_result.get_status()

            # Invoking record:a and record:aaaa for hostname
            else:
                record_a_params = {
                    consts.INFOBLOX_JSON_RETURN_FIELDS: consts.INFOBLOX_RECORD_A_RETURN_FIELDS,
                    "{}{}".format(consts.INFOBLOX_JSON_RECORD_NAME, "~"): ip_hostname,
                    consts.INFOBLOX_PARAM_VIEW: consts.INFOBLOX_NETWORK_VIEW_DEFAULT
                }

                # Make call to get lease information
                host_status, host_response = self._make_rest_call(consts.INFOBLOX_RECORDS_IPv4_ENDPOINT,
                                                                  action_result, params=record_a_params,
                                                                  method="get")

                # Something went wrong
                if phantom.is_fail(host_status):
                    return action_result.get_status()

                # if response from record:a is empty list, invoke record:aaaa
                if not host_response[consts.INFOBLOX_RESPONSE_DATA]:
                    record_aaaa_params = {
                        consts.INFOBLOX_JSON_RETURN_FIELDS: consts.INFOBLOX_RECORD_AAAA_RETURN_FIELDS,
                        "{}{}".format(consts.INFOBLOX_JSON_RECORD_NAME, "~"): ip_hostname,
                        consts.INFOBLOX_PARAM_VIEW: consts.INFOBLOX_NETWORK_VIEW_DEFAULT
                    }

                    # Make call to get lease information
                    host_status, host_response = self._make_rest_call(consts.INFOBLOX_RECORDS_IPv6_ENDPOINT,
                                                                      action_result, params=record_aaaa_params,
                                                                      method="get")

                    # Something went wrong
                    if phantom.is_fail(host_status):
                        return action_result.get_status()

            host_response_list = host_response[consts.INFOBLOX_RESPONSE_DATA]

        # If information for a given host is unavailable
        if not lease_response_list and not host_response_list:
            self.debug_print(consts.INFOBLOX_HOST_INFO_UNAVAILABLE)
            return action_result.set_status(phantom.APP_SUCCESS, consts.INFOBLOX_HOST_INFO_UNAVAILABLE)

        # For Static IP, lease result would be empty and host list will have details
        if not lease_response_list and host_response_list:
            for host_data in host_response_list:
                data = {}
                # Post processing the output, to change ipv4addr key to IP
                client_host_name = host_data.get('name')
                zone = '.{}'.format(host_data['zone'])
                if client_host_name.endswith(zone):
                    client_host_name = client_host_name[:-len(zone)]
                if not (phantom.is_ip(ip_hostname) or _is_ipv6(ip_hostname)):
                    if client_host_name != ip_hostname:
                        continue
                data[consts.INFOBLOX_JSON_CLIENT_HOSTNAME] = client_host_name
                data[consts.INFOBLOX_JSON_HARDWARE] = host_data.get('discovered_data', {}).get('mac_address')
                data[consts.INFOBLOX_JSON_OS] = host_data.get('discovered_data', {}).get('os')
                data[consts.INFOBLOX_JSON_ADDRESS] = host_data.get(consts.INFOBLOX_JSON_A_IP,
                                                                   host_data.get(consts.INFOBLOX_JSON_AAAA_IP))
                if phantom.is_ip(host_data.get(consts.INFOBLOX_JSON_A_IP)):
                    data[consts.INFOBLOX_JSON_PROTOCOL] = "IPV4"
                elif phantom.is_ip(host_data.get(consts.INFOBLOX_JSON_AAAA_IP)):
                    data[consts.INFOBLOX_JSON_PROTOCOL] = "IPV6"

                summary_data["mac_address"] = data[consts.INFOBLOX_JSON_HARDWARE]
                summary_data["is_static_ip"] = True
                action_result.add_data(data)

        for data in lease_response_list:
            # Filter the host information details
            host_data = None
            if host_response_list:
                host_data = [host for host in host_response_list if (host['ipv4addr'] == data['address'] or host['ipv6addr'] == data['address'])]
            if host_data:
                data['os'] = host_data[0].get('discovered_data', {}).get('os')
            # Converting epoch seconds to "%Y-%m-%d %H:%M:%S" date format
            data[consts.INFOBLOX_JSON_CLTT] = time.strftime(consts.INFOBLOX_JSON_DATE_FORMAT,
                                                            time.localtime(data[consts.INFOBLOX_JSON_CLTT]))
            data[consts.INFOBLOX_JSON_STARTS] = time.strftime(consts.INFOBLOX_JSON_DATE_FORMAT,
                                                              time.localtime(data[consts.INFOBLOX_JSON_STARTS]))
            data[consts.INFOBLOX_JSON_ENDS] = time.strftime(consts.INFOBLOX_JSON_DATE_FORMAT,
                                                            time.localtime(data[consts.INFOBLOX_JSON_ENDS]))
            summary_data["mac_address"] = data["hardware"]
            summary_data["binding_state"] = data["binding_state"]
            summary_data["never_ends"] = data["never_ends"]
            summary_data["is_static_ip"] = False
            action_result.add_data(data)

        if not action_result.get_data_size():
            self.debug_print(consts.INFOBLOX_HOST_INFO_UNAVAILABLE)
            return action_result.set_status(phantom.APP_SUCCESS, consts.INFOBLOX_HOST_INFO_UNAVAILABLE)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _list_network_view(self, param):
        """ Get list of network view from infobloxddi.

        :param param: dictionary of input parameter
        :return: status (success/failure)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Make call to obtain list of network view
        status, response = self._make_paged_rest_call(
            consts.INFOBLOX_NETWORK_VIEW,
            action_result,
            method="get"
        )

        # Something went wrong
        if phantom.is_fail(status):
            return action_result.get_status()

        # If network view information is unavailable
        if not response:
            self.debug_print(consts.INFOBLOX_NETWORK_VIEW_INFO_UNAVAILABLE)
            return action_result.set_status(phantom.APP_ERROR, consts.INFOBLOX_NETWORK_VIEW_INFO_UNAVAILABLE)

        for data in response:
            action_result.add_data(data)

        # Update summary data
        summary_data["total_network_view"] = len(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _block_domain(self, param):
        """ Function to add entry of domain to provided Response Policy Zone in a blocked state.

        :param param: dictionary of input parameter
        :return: status (success/failure)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Mandatory parameters
        domain_name = param[consts.INFOBLOX_JSON_DOMAIN]
        # Convert URL to domain
        if phantom.is_url(domain_name):
            domain_name = phantom.get_host_from_url(domain_name)

        rp_zone = param[consts.INFOBLOX_JSON_RP_ZONE]

        # Optional parameters
        view = param.get(consts.INFOBLOX_JSON_NETWORK_VIEW, consts.INFOBLOX_NETWORK_VIEW_DEFAULT)
        comment = param.get(consts.INFOBLOX_JSON_COMMENT)

        rpz_rule_name = "{domain_name}.{rp_zone}".format(domain_name=domain_name, rp_zone=rp_zone)

        self.send_progress(consts.INFOBLOX_VALIDATE_MESSAGE)

        # Checking if given rp_zone exists
        zone_details_param = {consts.INFOBLOX_PARAM_FQDN: rp_zone, consts.INFOBLOX_PARAM_VIEW: view}
        rp_zone_exists_status = self._validate_rp_zone(action_result, zone_details_param)

        # If validation fails
        if phantom.is_fail(rp_zone_exists_status):
            return action_result.get_status()

        # Updating cookie "ibapauth" for authentication
        self._sess_obj.headers.update({"ibapauth": self._sess_obj.cookies["ibapauth"]})

        # Checking if RPZ rule name exists in given rp_zone
        check_rpz_rule_params = {
            consts.INFOBLOX_RPZ_RULE_NAME: rpz_rule_name,
            consts.INFOBLOX_PARAM_ZONE: rp_zone,
            consts.INFOBLOX_PARAM_VIEW: view
        }
        check_name_details_status, rpz_rule_name_details = self._make_rest_call(consts.INFOBLOX_DOMAIN_ENDPOINT,
                                                                                action_result,
                                                                                params=check_rpz_rule_params,
                                                                                method="get")
        # Something went wrong while getting details of RPZ rule name
        if phantom.is_fail(check_name_details_status):
            return action_result.get_status()

        # Checking if given RPZ rule name already exists in given RP zone.
        if rpz_rule_name_details.get(consts.INFOBLOX_RESPONSE_DATA):

            # If RPZ rule name exists, then it must be in blocked state(No Such Domain Rule)
            if rpz_rule_name_details[consts.INFOBLOX_RESPONSE_DATA][0].get(consts.INFOBLOX_PARAM_CANONICAL) != "":
                self.debug_print(consts.INFOBLOX_DOMAIN_EXISTS_NOT_IN_BLOCKED_STATE)
                return action_result.set_status(phantom.APP_ERROR, consts.INFOBLOX_DOMAIN_EXISTS_NOT_IN_BLOCKED_STATE)

            # If RPZ rule name exists with blocked state(No Such Domain Rule)
            self.debug_print(consts.INFOBLOX_DOMAIN_ALREADY_BLOCKED)
            return action_result.set_status(phantom.APP_SUCCESS, consts.INFOBLOX_DOMAIN_ALREADY_BLOCKED)

        api_data = {
            consts.INFOBLOX_RPZ_RULE_NAME: rpz_rule_name, consts.INFOBLOX_JSON_RP_ZONE: rp_zone,
            consts.INFOBLOX_PARAM_CANONICAL: "", consts.INFOBLOX_PARAM_VIEW: view
        }

        # If comment is provided to block domain
        if comment:
            api_data[consts.INFOBLOX_JSON_COMMENT] = comment

        # Make call to block domain
        status, response = self._make_rest_call(consts.INFOBLOX_DOMAIN_ENDPOINT, action_result, data=api_data)

        # Something went wrong while blocking domain
        if phantom.is_fail(status):
            return action_result.get_status()

        action_result.add_data({consts.INFOBLOX_REFERENCE_LINK: response.get(consts.INFOBLOX_RESPONSE_DATA)})

        return action_result.set_status(phantom.APP_SUCCESS, consts.INFOBLOX_BLOCK_DOMAIN_SUCCESS)

    def _block_ip(self, param):
        """ Function to add entry of IP to provided Response Policy Zone in a blocked state.

        :param param: dictionary of input parameter
        :return: status (success/failure)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Mandatory parameters
        ip_address = param[consts.INFOBLOX_JSON_IP]
        rp_zone = param[consts.INFOBLOX_JSON_RP_ZONE]

        # Optional parameters
        view = param.get(consts.INFOBLOX_JSON_NETWORK_VIEW, consts.INFOBLOX_NETWORK_VIEW_DEFAULT)
        comment = param.get(consts.INFOBLOX_JSON_COMMENT)

        self.send_progress(consts.INFOBLOX_VALIDATE_MESSAGE)

        rpz_rule_name = "{ip_address}.{rpz}".format(ip_address=ip_address.lower(), rpz=rp_zone)

        # Checking if given rp_zone exists
        zone_details_param = {consts.INFOBLOX_PARAM_FQDN: rp_zone, consts.INFOBLOX_PARAM_VIEW: view}
        rp_zone_exists_status = self._validate_rp_zone(action_result, zone_details_param)

        # If validation fails
        if phantom.is_fail(rp_zone_exists_status):
            return action_result.get_status()

        # Updating cookie "ibapauth" for authentication
        self._sess_obj.headers.update({"ibapauth": self._sess_obj.cookies["ibapauth"]})

        # Checking if RPZ rule name exists in given rp_zone
        check_rpz_rule_params = {
            consts.INFOBLOX_RPZ_RULE_NAME: rpz_rule_name,
            consts.INFOBLOX_PARAM_ZONE: rp_zone,
            consts.INFOBLOX_PARAM_VIEW: view
        }
        check_name_details_status, rpz_rule_name_details = self._make_rest_call(consts.INFOBLOX_IP_ENDPOINT,
                                                                                action_result,
                                                                                params=check_rpz_rule_params,
                                                                                method="get")

        # Something went wrong while getting details of RPZ rule name
        if phantom.is_fail(check_name_details_status):
            return action_result.get_status()

        # Checking if given RPZ rule name already exists in given RP zone
        if rpz_rule_name_details.get(consts.INFOBLOX_RESPONSE_DATA):
            # If RPZ rule name exists, then it must be in blocked state(No Such Domain Rule)
            if rpz_rule_name_details[consts.INFOBLOX_RESPONSE_DATA][0].get(consts.INFOBLOX_PARAM_CANONICAL) != "":
                self.debug_print(consts.INFOBLOX_IP_EXISTS_NOT_IN_BLOCKED_STATE)
                return action_result.set_status(phantom.APP_ERROR, consts.INFOBLOX_IP_EXISTS_NOT_IN_BLOCKED_STATE)

            # If RPZ rule name exists with blocked(No Such Domain Rule) state
            self.debug_print(consts.INFOBLOX_IP_ALREADY_BLOCKED)
            return action_result.set_status(phantom.APP_SUCCESS, consts.INFOBLOX_IP_ALREADY_BLOCKED)

        api_data = {
            consts.INFOBLOX_RPZ_RULE_NAME: rpz_rule_name, consts.INFOBLOX_JSON_RP_ZONE: rp_zone,
            consts.INFOBLOX_PARAM_CANONICAL: "", consts.INFOBLOX_PARAM_VIEW: view
        }

        # If comment is provided to block IP
        if comment:
            api_data[consts.INFOBLOX_JSON_COMMENT] = comment

        # Make call to block IP
        status, response = self._make_rest_call(consts.INFOBLOX_IP_ENDPOINT, action_result, params=api_data)

        # Something went wrong while blocking IP
        if phantom.is_fail(status):
            return action_result.get_status()

        action_result.add_data({consts.INFOBLOX_REFERENCE_LINK: response.get(consts.INFOBLOX_RESPONSE_DATA)})

        return action_result.set_status(phantom.APP_SUCCESS, consts.INFOBLOX_BLOCK_IP_SUCCESS)

    def _unblock_ip(self, param):
        """ Function to remove entry of IP from provided Response Policy Zone.

        :param param: dictionary of input parameter
        :return: status (success/failure)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Mandatory parameters
        ip_address = param[consts.INFOBLOX_JSON_IP]
        rp_zone = param[consts.INFOBLOX_JSON_RP_ZONE]

        # Optional parameter
        view = param.get(consts.INFOBLOX_JSON_NETWORK_VIEW, consts.INFOBLOX_NETWORK_VIEW_DEFAULT)

        self.send_progress(consts.INFOBLOX_VALIDATE_MESSAGE)

        rpz_rule_name = "{ip_address}.{rpz}".format(ip_address=ip_address.lower(), rpz=rp_zone)

        # Checking if given rp_zone exists
        zone_details_param = {consts.INFOBLOX_PARAM_FQDN: rp_zone, consts.INFOBLOX_PARAM_VIEW: view}
        rp_zone_exists_status = self._validate_rp_zone(action_result, zone_details_param)

        # If validation fails
        if phantom.is_fail(rp_zone_exists_status):
            return action_result.get_status()

        # Updating cookie "ibapauth" for authentication
        self._sess_obj.headers.update({"ibapauth": self._sess_obj.cookies["ibapauth"]})

        # Checking if RPZ rule name exists in given rp_zone
        check_rpz_rule_params = {
            consts.INFOBLOX_RPZ_RULE_NAME: rpz_rule_name,
            consts.INFOBLOX_PARAM_ZONE: rp_zone,
            consts.INFOBLOX_PARAM_VIEW: view
        }
        check_name_details_status, rpz_rule_name_details = self._make_rest_call(consts.INFOBLOX_IP_ENDPOINT,
                                                                                action_result,
                                                                                params=check_rpz_rule_params,
                                                                                method="get")

        # Something went wrong while getting details of RPZ rule name
        if phantom.is_fail(check_name_details_status):
            return action_result.get_status()

        # Checking if given RPZ rule name exists in given RP zone
        if not rpz_rule_name_details.get(consts.INFOBLOX_RESPONSE_DATA):
            self.debug_print(consts.INFOBLOX_IP_ALREADY_UNBLOCKED)
            return action_result.set_status(phantom.APP_SUCCESS, consts.INFOBLOX_IP_ALREADY_UNBLOCKED)

        # If RPZ rule name exists, then it must be in blocked state(No Such Domain Rule)
        if rpz_rule_name_details[consts.INFOBLOX_RESPONSE_DATA][0].get(consts.INFOBLOX_PARAM_CANONICAL) != "":
            self.debug_print(consts.INFOBLOX_IP_NOT_IN_BLOCKED_STATE)
            return action_result.set_status(phantom.APP_ERROR, consts.INFOBLOX_IP_NOT_IN_BLOCKED_STATE)

        # Unblocking provided IP address
        ref = rpz_rule_name_details[consts.INFOBLOX_RESPONSE_DATA][0].get("_ref")

        unblock_status, unblock_response = self._make_rest_call("/{ref}".format(ref=ref), action_result,
                                                                method="delete")

        # Something went wrong while unblocking IP address
        if phantom.is_fail(unblock_status):
            return action_result.get_status()

        action_result.add_data({consts.INFOBLOX_REFERENCE_LINK: unblock_response.get(consts.INFOBLOX_RESPONSE_DATA)})

        return action_result.set_status(phantom.APP_SUCCESS, consts.INFOBLOX_IP_UNBLOCK_SUCCESS)

    def _unblock_domain(self, param):
        """ Function to remove entry of domain from provided Response Policy Zone.

        :param param: dictionary of input parameter
        :return: status (success/failure)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Mandatory parameters
        domain_name = param[consts.INFOBLOX_JSON_DOMAIN]
        # Convert URL to domain
        if phantom.is_url(domain_name):
            domain_name = phantom.get_host_from_url(domain_name)

        rp_zone = param[consts.INFOBLOX_JSON_RP_ZONE]

        # Optional parameter
        view = param.get(consts.INFOBLOX_JSON_NETWORK_VIEW, consts.INFOBLOX_NETWORK_VIEW_DEFAULT)

        rpz_rule_name = "{domain}.{rpz}".format(domain=domain_name, rpz=rp_zone)

        # Checking if given rp_zone exists
        zone_details_param = {consts.INFOBLOX_PARAM_FQDN: rp_zone, consts.INFOBLOX_PARAM_VIEW: view}
        rp_zone_exists_status = self._validate_rp_zone(action_result, zone_details_param)

        # If validation fails
        if phantom.is_fail(rp_zone_exists_status):
            return action_result.get_status()

        # Updating cookie "ibapauth" for authentication
        self._sess_obj.headers.update({"ibapauth": self._sess_obj.cookies["ibapauth"]})

        # Checking if RPZ rule name exists in given rp_zone
        check_rpz_rule_params = {
            consts.INFOBLOX_RPZ_RULE_NAME: rpz_rule_name,
            consts.INFOBLOX_PARAM_ZONE: rp_zone,
            consts.INFOBLOX_PARAM_VIEW: view
        }
        check_name_details_status, rpz_rule_name_details = self._make_rest_call(consts.INFOBLOX_DOMAIN_ENDPOINT,
                                                                                action_result,
                                                                                params=check_rpz_rule_params,
                                                                                method="get")

        # Something went wrong while getting details of RPZ rule name
        if phantom.is_fail(check_name_details_status):
            return action_result.get_status()

        # Checking if given RPZ rule name exists in given RP zone
        if not rpz_rule_name_details.get(consts.INFOBLOX_RESPONSE_DATA):
            self.debug_print(consts.INFOBLOX_DOMAIN_ALREADY_UNBLOCKED)
            return action_result.set_status(phantom.APP_SUCCESS, consts.INFOBLOX_DOMAIN_ALREADY_UNBLOCKED)

        # If RPZ rule name exists, then it must be in blocked state(No Such Domain Rule)
        if rpz_rule_name_details[consts.INFOBLOX_RESPONSE_DATA][0].get(consts.INFOBLOX_PARAM_CANONICAL) != "":
            self.debug_print(consts.INFOBLOX_DOMAIN_NOT_IN_BLOCKED_STATE)
            return action_result.set_status(phantom.APP_ERROR, consts.INFOBLOX_DOMAIN_NOT_IN_BLOCKED_STATE)

        # Unblocking provided domain
        ref = rpz_rule_name_details[consts.INFOBLOX_RESPONSE_DATA][0].get("_ref")

        unblock_status, unblock_response = self._make_rest_call("/{ref}".format(ref=ref), action_result,
                                                                method="delete")

        # Something went wrong while unblocking domain
        if phantom.is_fail(unblock_status):
            return action_result.get_status()

        action_result.add_data({consts.INFOBLOX_REFERENCE_LINK: unblock_response.get(consts.INFOBLOX_RESPONSE_DATA)})

        return action_result.set_status(phantom.APP_SUCCESS, consts.INFOBLOX_DOMAIN_UNBLOCK_SUCCESS)

    def _list_rpz(self, param):
        """ Function to list details of RPZ (Response Policy Zone).

        :param param: Network view to list Response Policy Zone
        :return: status (success/failure)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Providing optional parameter in object
        zone_details_param = {consts.INFOBLOX_PARAM_VIEW: param.get(consts.INFOBLOX_JSON_NETWORK_VIEW,
                                                                    consts.INFOBLOX_NETWORK_VIEW_DEFAULT)}

        # Getting RPZ details
        rp_zone_details_status, rp_zone_details = self._get_rp_zone_details(action_result, zone_details_param)

        if phantom.is_fail(rp_zone_details_status):
            return action_result.get_status()

        if isinstance(rp_zone_details, dict) and rp_zone_details.get(consts.INFOBLOX_RESOURCE_NOT_FOUND):
            return action_result.set_status(phantom.APP_ERROR, rp_zone_details.get("error_message", consts.INFOBLOX_LIST_RPZ_NON_DEF_MESSAGE))

        summary_data[consts.INFOBLOX_TOTAL_RESPONSE_POLICY_ZONES] = len(rp_zone_details)

        for rp_zone_detail in rp_zone_details:
            if rp_zone_detail.get(consts.INFOBLOX_LAST_UPDATED_TIME):
                # Converting epoch seconds to "%Y-%m-%d %H:%M:%S" date format
                rp_zone_detail[consts.INFOBLOX_LAST_UPDATED_TIME] = time.strftime(
                    consts.INFOBLOX_JSON_DATE_FORMAT, time.localtime(rp_zone_detail[consts.INFOBLOX_LAST_UPDATED_TIME])
                )
            action_result.add_data(rp_zone_detail)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _list_hosts(self, param):
        """ List hosts managed/added by infobloxddi.

        :param param: dictionary of input parameters
        :return: list of hosts
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        ipv4_hosts_param = {consts.INFOBLOX_JSON_RETURN_FIELDS: "ipv4addr,name,view,zone"}

        # Getting list of ipv4 hosts
        ipv4_hosts_status, ipv4_hosts = self._make_paged_rest_call(
            consts.INFOBLOX_RECORDS_IPv4_ENDPOINT,
            action_result,
            params=ipv4_hosts_param,
            method="get"
        )

        # Something went wrong while getting ipv4 host details
        if phantom.is_fail(ipv4_hosts_status):
            self.debug_print(consts.INFOBLOX_LIST_HOSTS_ERROR)
            return action_result.get_status()

        # Loop through all the hosts and add to action_result
        for ipv4_host in ipv4_hosts:
            # Post processing the output, to change ipv4addr key to IP
            ipv4_host['ip'] = ipv4_host.pop('ipv4addr')
            zone = '.{}'.format(ipv4_host['zone'])
            if ipv4_host['name'].endswith(zone):
                ipv4_host['name'] = ipv4_host['name'][:-len(zone)]
            action_result.add_data(ipv4_host)

        # Getting list of ipv6 hosts
        ipv6_hosts_param = {consts.INFOBLOX_JSON_RETURN_FIELDS: "ipv6addr,name,view,zone"}

        ipv6_hosts_status, ipv6_hosts = self._make_paged_rest_call(
            consts.INFOBLOX_RECORDS_IPv6_ENDPOINT,
            action_result,
            params=ipv6_hosts_param,
            method="get"
        )

        # Something went wrong while getting ipv6 host details
        if phantom.is_fail(ipv6_hosts_status):
            self.debug_print(consts.INFOBLOX_LIST_HOSTS_ERROR)
            return action_result.get_status()

        # Loop through all the hosts and add to action_result
        for ipv6_host in ipv6_hosts:
            # Post processing the output, to change ipv4addr key to IP
            ipv6_host['ip'] = ipv6_host.pop('ipv6addr')
            zone = '.{}'.format(ipv6_host['zone'])
            if ipv6_host['name'].endswith(zone):
                ipv6_host['name'] = ipv6_host['name'][:-len(zone)]
            action_result.add_data(ipv6_host)

        summary_data[consts.INFOBLOX_TOTAL_HOSTS] = len(ipv4_hosts) + len(ipv6_hosts)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status (success/failure)
        """

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            "test_asset_connectivity": self._test_asset_connectivity,
            "get_system_info": self._get_system_info,
            "block_domain": self._block_domain,
            "block_ip": self._block_ip,
            "unblock_ip": self._unblock_ip,
            "unblock_domain": self._unblock_domain,
            "list_rpz": self._list_rpz,
            "list_hosts": self._list_hosts,
            "list_network_view": self._list_network_view,
            "get_network_info": self._get_network_info
        }

        action = self.get_action_identifier()

        try:
            run_action = action_mapping[action]
        except Exception:
            raise ValueError("action {action} is not supported".format(action=action))

        return run_action(param)

    def finalize(self):
        """ This function gets called once all the param dictionary elements are looped over and no more handle_action
        calls are left to be made. It gives the AppConnector a chance to loop through all the results that were
        accumulated by multiple handle_action function calls and create any summary if required. Another usage is
        cleanup, disconnect from remote devices etc.

        :return: status (success/failure)
        """

        self.save_state(self._state)
        return self._logout()


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = '{}/login'.format(InfobloxddiConnector._get_phantom_base_url())

            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=consts.DEFAULT_REQUEST_TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={}'.format(csrftoken)
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=consts.DEFAULT_REQUEST_TIMEOUT)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: {}".format(str(e)))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = InfobloxddiConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)


if __name__ == '__main__':
    main()
