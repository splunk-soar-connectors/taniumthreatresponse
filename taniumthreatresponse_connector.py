# File: taniumthreatresponse_connector.py
#
# Copyright (c) 2020-2022 Splunk Inc.
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
# Phantom App imports
import json
import os
import sys
import tempfile
import uuid

import phantom.app as phantom
import phantom.rules as ph_rules
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from phantom.vault import Vault

from taniumthreatresponse_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class TaniumThreatResponseConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(TaniumThreatResponseConnector, self).__init__()

        self._state = dict()
        self._python_version = None
        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._api_token = None
        self._username = None
        self._password = None
        self._session_key = None
        self._verify_server_cert = None

    def _validate_integer(self, action_result, parameter, key, allow_zero=True):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MSG.format(key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MSG.format(key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, NON_NEGATIVE_INTEGER_MSG.format(key)), None

            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, NON_ZERO_POSITIVE_INTEGER_MSG.format(key)), None

        return phantom.APP_SUCCESS, parameter

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error messages from the exception.
        :param e: Exception object
        :return: error message
        """

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = ERR_CODE_MSG
                    error_msg = e.args[0]
            else:
                error_code = ERR_CODE_MSG
                error_msg = ERR_MSG_UNAVAILABLE
        except:
            error_code = ERR_CODE_MSG
            error_msg = ERR_MSG_UNAVAILABLE

        try:
            if error_code in ERR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
        except:
            self.debug_print(PARSE_ERR_MSG)
            error_text = PARSE_ERR_MSG

        return error_text

    def _process_empty_response(self, response, action_result):

        if int(response.status_code) >= 200 and int(response.status_code) <= 299:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(
            phantom.APP_ERROR, 'Status code {}: Empty response and no information in the header'.format(response.status_code)), None)

    def _process_content_response(self, response, action_result):
        """ Process plain content from an API call. Can be used for downloading files.

        Args:
            response (Response): response from API request
            action_result (ActionResult): object of ActionResult class

        Returns:
            RetVal:
                * ActionResult: status success/failure
                * Response or None:
        """

        if 200 <= response.status_code < 400:
            return RetVal(phantom.APP_SUCCESS, response)

        message = 'Error from server. Status code: {0}'.format(response.status_code)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            # Remove the script and style from the HTML message
            for element in soup(["script", "style", "footer", "nav", "title"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = 'Cannot parse error details'

        message = 'Status Code: {0}. Data from server:\n{1}\n'.format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Unable to parse JSON response. Error: {0}'.format(err)), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = 'Error from server. Status Code: {0} Data from server: {1}'.format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # If it is a file download, process before getting debug data
        if 'octet' in r.headers.get('Content-Type', ''):
            return self._process_content_response(r, action_result)

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        if 'zip' in r.headers.get('Content-Type', ''):
            return self._process_content_response(r, action_result)

        # it's not a content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        if r.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, r.text)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _get_token(self, action_result, from_action=False):
        """ This function is used to get a token via REST Call.

        :param action_result: Object of action result
        :param from_action: Boolean object of from_action
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        config = self.get_config()
        username = config.get('username')
        auth = (username, config.get('password'))
        headers = {
            'Content-Type': 'application/json'
        }

        ret_val, resp_json = self._make_rest_call("{}{}".format(
            self._base_url, "/auth"), action_result, verify=self._verify_server_cert, headers=headers, auth=auth, method='post')

        if phantom.is_fail(ret_val):
            self._state['session_key'] = None
            self._session_key = None
            # self.save_state(self._state)
            return action_result.get_status()

        self._state['session_key'] = resp_json
        self._session_key = resp_json
        # self.save_state(self._state)

        return phantom.APP_SUCCESS

    def _make_rest_call_helper(self, endpoint, action_result, headers=None, params=None, data=None, json=None, method="get"):
        """ Function that helps setting REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param verify: verify server certificate (Default True)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        try:
            url = "{0}{1}".format(self._base_url, endpoint)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, "Please check the asset configuration and action parameters. Error: {0}".format(err)), None

        if headers is None:
            headers = {}

        if not self._session_key:
            ret_val = self._get_token(action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

        headers.update({'session': str(self._session_key)})
        if 'Content-Type' not in list(headers.keys()):
            headers.update({'Content-Type': 'application/json'})

        ret_val, resp_json = self._make_rest_call(
            url, action_result, verify=self._verify_server_cert, headers=headers, params=params, data=data, json=json, method=method)

        # If token is expired, generate a new token
        msg = action_result.get_message()

        if msg and ("HTTP 401: Unauthorized" in msg or "403" in msg):
            ret_val = self._get_token(action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None
            headers.update({'session': str(self._session_key)})
            if 'Content-Type' not in list(headers.keys()):
                headers.update({'Content-Type': 'application/json'})

            ret_val, resp_json = self._make_rest_call(
                url, action_result, verify=self._verify_server_cert, headers=headers, params=params, data=data, json=json, method=method)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, resp_json

    def _make_rest_call(self, endpoint, action_result, verify=True, headers=None, params=None, data=None, json=None, auth=None, method="get"):
        """ Function that makes the REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param verify: verify server certificate (Default True)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """
        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        try:
            r = request_func(endpoint, json=json, data=data, headers=headers, verify=verify,
                                auth=auth, params=params, timeout=DEFAULT_REQUEST_TIMEOUT)
        except requests.exceptions.InvalidSchema:
            error_message = 'Error connecting to server. No connection adapters were found for %s' % (endpoint)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except requests.exceptions.InvalidURL:
            error_message = 'Error connecting to server. Invalid URL %s' % (endpoint)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except requests.exceptions.ConnectionError:
            error_message = "Error Details: Connection Refused from the Server"
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(err)), resp_json)

        return self._process_response(r, action_result)

    def _get_filename_from_tanium(self, action_result, file_id):

        filename = None

        ret_val, response = self._make_rest_call_helper(LIST_FILE_EVIDENCE_ENDPOINT, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('List Files Failed')
            return RetVal(action_result.get_status(), None)

        if 'fileEvidence' in response:
            for f in response['fileEvidence']:
                if f.get('uuid') == file_id:
                    filename = f.get('path', '').split('\\')[-1]
                    break

        return RetVal(phantom.APP_SUCCESS, filename)

    def _save_temp_file(self, content):
        """

        Args:
            content:

        Returns:

        """

        if hasattr(Vault, 'get_vault_tmp_dir'):
            temp_dir = Vault.get_vault_tmp_dir()
        else:
            temp_dir = '/opt/phantom/vault/tmp'

        temp_dir = '{}/{}'.format(temp_dir, uuid.uuid4())
        os.makedirs(temp_dir)

        file_obj = tempfile.NamedTemporaryFile(prefix='taniumthreatresponse_',
                                               dir=temp_dir,
                                               delete=False)
        file_obj.close()

        with open(file_obj.name, 'wb') as f:
            f.write(content)

        return file_obj.name

    def _list_connections(self, action_result):
        """ Return a list of current connections.

        Args:
            action_result (ActionResult): object of ActionResult class

        Returns:
            RetVal:
                bool: Success/ Failure
                list: Current connections in Tanium Threat Response

        """

        ret_val, response = self._make_rest_call_helper(LIST_CONNECTIONS_ENDPOINT, action_result)

        if phantom.is_fail(ret_val):
            message = action_result.get_message()
            return RetVal(action_result.set_status(
                phantom.APP_ERROR, 'Unable to list connections{}'.format('. Error message: {}'.format(message) if message else "")), None)

        return RetVal(phantom.APP_SUCCESS, response)

    def _is_connection_active(self, action_result, conn_id):
        """ Check to see if connection exists and is active.

        Args:
            action_result (ActionResult): object of ActionResult class
            conn_id (str): Connection ID to check if it is active

        Returns:
            bool: Success/ Failure
        """

        ret_val, response = self._list_connections(action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for connection in response:
            if conn_id == connection.get('id', ''):
                # state = connection.get('info', {}).get('state', '')
                status = connection.get('status', '')
                if status == 'connected':
                    return phantom.APP_SUCCESS
                elif not status:
                    message = 'Connection not active. Error occurred while fetching the state of the connection'
                    return action_result.set_status(phantom.APP_ERROR, message)
                else:
                    message = 'Connection not active. Current state: {}'.format(status)
                    return action_result.set_status(phantom.APP_ERROR, message)

        message = 'Could not find connection'
        return action_result.set_status(phantom.APP_ERROR, message)

    def _handle_test_connectivity(self, param):
        """ Test connectivity by listing the current connections

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        # self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._api_token:
            ret_val = self._get_token(action_result)

        ret_val, response = self._make_rest_call_helper(STATUS_ENDPOINT, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('Test Connectivity Failed')
            return action_result.get_status()

        # self.save_progress(response)
        self.save_progress('Test Connectivity Passed')
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_connections(self, param):
        """ List the current connections

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, response = self._list_connections(action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('List connections failed')
            return action_result.get_status()

        summary = action_result.update_summary({})
        try:
            for status in [x['status'] for x in response if 'status' in x]:
                summary['{}_connections'.format(
                    CONNECTION_STATUS[status])] = len([x for x in response if 'status' in x and x['status'] == status])
            for r in response:
                action_result.add_data(r)
                summary['total_connections'] = len(response)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing the response from server. {}".format(err))

        self.save_progress('List connections successful')
        message = 'Number of active connections found: {}'.format(summary.get('active_connections', 0))
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_get_endpoint_helper(self, param, action_result):
        """ Get endpoint information.

        Args:
            param (dict)

        """
        self.save_progress('In get endpoint helper function')

        dst = param.get('destination')
        dsttype = param.get('destination_type')

        if dsttype not in (DSTTYPE_VALUE_LIST or DSTTYPE_PARAMETER_NAME):
            return action_result.set_status(
                phantom.APP_ERROR, "Please provide valid input from {} in 'destination_type' action parameter".format(DSTTYPE_VALUE_LIST)), None
        params = {}
        params[DSTTYPE_PARAMETER_NAME[dsttype]] = dst

        ret_val, response = self._make_rest_call_helper(GET_ENDPOINT_API_ENDPOINT, action_result, params=params, method="get")

        return ret_val, response

    def _handle_get_endpoint(self, param):
        """ Get endpoint information.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure

        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, response = self._handle_get_endpoint_helper(param, action_result)

        if phantom.is_fail(ret_val) or not response.get('data'):
            self.save_progress('Get endpoint failed')
            return action_result.get_status()

        if 'data' in response:
            for item in response['data']:
                action_result.add_data(item)
        else:
            action_result.add_data(response)

        self.save_progress('Get endpoint successful')
        message = 'Endpoint information found'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_create_connection(self, param):
        """ Create connection to a live endpoint.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get required endpoint information in order to make a connection
        ret_val, response = self._handle_get_endpoint_helper(param, action_result)
        if phantom.is_fail(ret_val) or not response.get('data'):
            message = "Get endpoint info for new connection failed"
            self.save_progress(message)
            return action_result.set_status(phantom.APP_ERROR, message)

        payload = {"target": {}}
        data = response.get('data')[0]
        for item in CREATE_CONNECTION_REQUIRED_FIELD_LIST:
            if item not in data:
                return action_result.set_status(phantom.APP_ERROR, "Endpoint data lookup failure in {}".format(self.get_action_identifier()))
            else:
                payload['target'][item] = data[item]

        ret_val, response = self._make_rest_call_helper(CREATE_CONNECTION_ENDPOINT, action_result, json=payload, method='post')

        if phantom.is_fail(ret_val):
            self.save_progress('Create connection failed')
            return action_result.get_status()

        message = "Create connection successful"
        self.save_progress(message)

        action_result.add_data({'id': response})

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_close_connection(self, param):
        """ Close a user connection.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        cid = param.get('connection_id')

        ret_val, response = self._make_rest_call_helper(CLOSE_CONNECTION_ENDPOINT.format(cid=cid), action_result, method="delete")

        if phantom.is_fail(ret_val):
            self.save_progress('Close connection failed')
            return action_result.get_status()

        action_result.add_data(response)

        self.save_progress('Close connection successful')
        message = 'Connection is closed'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_delete_connection(self, param):
        """ Deletes specified connection.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        cid = param.get('connection_id')

        ret_val, response = self._make_rest_call_helper(DELETE_CONNECTION_ENDPOINT.format(cid=cid), action_result, method='delete')

        if phantom.is_fail(ret_val):
            self.save_progress('Delete connection failed')
            return action_result.get_status()

        self.save_progress('Delete connection successful')
        message = 'Delete connection requested'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_list_snapshots(self, param):
        """ List existing snapshots.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}
        if 'limit' in param:
            params['limit'] = param['limit']

        if 'offset' in param:
            params['offset'] = param['offset']

        if 'sort' in param:
            params['sort'] = param['sort']

        ret_val, response = self._make_rest_call_helper(GET_ALL_SNAPSHOTS_ENDPOINT, action_result, params=params)

        if phantom.is_fail(ret_val):
            self.save_progress('List snapshots failed')
            return action_result.get_status()

        if 'snapshots' in response:
            for snapshot in response['snapshots']:
                action_result.add_data(snapshot)

        summary = action_result.update_summary({})
        if 'totalCount' in response:
            summary['total_snapshots'] = response['totalCount']
        else:
            summary['total_snapshost'] = 0

        self.save_progress('List snapshots successful')
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_snapshot(self, param):
        """ Create new snapshot. Requires a connection to already be setup.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        cid = param['connection_id']

        if not self._is_connection_active(action_result, cid):
            self.save_progress('Inactive or non-existent connection')
            return action_result.get_status()

        # endpoint = '/plugin/products/trace/conns/{}/snapshots'.format(cid)
        ret_val, response = self._make_rest_call_helper(CREATE_SNAPSHOT_ENDPOINT.format(cid=cid), action_result, method='post')

        if phantom.is_fail(ret_val):
            self.save_progress('Create snapshot failed')
            return action_result.get_status()

        self.save_progress('Create snapshot successful')
        message = 'Create snapshot requested'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_delete_snapshot(self, param):
        """ Delete existing snapshot.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        snapshot_id = param['snapshot_id']

        request = {
            "ids": [
                snapshot_id
            ]
        }

        ret_val, response = self._make_rest_call_helper(DELETE_SNAPSHOT_ENDPOINT, action_result, json=request, method='delete')

        if phantom.is_fail(ret_val):
            self.save_progress('Delete snapshot failed')
            return action_result.get_status()

        self.save_progress('Delete snapshot successful')
        message = 'Delete snapshot requested'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_get_process(self, param):
        """ Get process information from an existing connection.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        cid = param['connection_id']
        ret_val, ptid = self._validate_integer(action_result, param.get('process_table_id'), PROCESS_TABLE_ID_KEY)
        type = "process"

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not self._is_connection_active(action_result, cid):
            self.save_progress('Inactive or non-existent connection')
            return action_result.get_status()

        ret_val, response = self._make_rest_call_helper(GET_PROCESS_DETAILS_ENDPOINT.format(cid=cid, ptid=ptid, type=type), action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('Get process failed')
            return action_result.get_status()

        for item in response:
            action_result.add_data(item)

        self.save_progress('Get process successful')
        message = 'Process information retrieved'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_get_process_tree(self, param):
        """ Get process tree for a process from an existing connection.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        cid = param['connection_id']
        ret_val, ptid = self._validate_integer(action_result, param.get('process_table_id'), PROCESS_TABLE_ID_KEY)
        ret_val, limit = self._validate_integer(action_result, param.get('limit'), LIMIT_KEY)
        process_context = param.get('process_context')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not self._is_connection_active(action_result, cid):
            self.save_progress('Inactive or non-existent connection')
            return action_result.get_status()

        params = {}
        if limit:
            params['limit'] = limit

        if process_context != 'all':
            params['context'] = process_context

        ret_val, response = self._make_rest_call_helper(GET_PROCESS_TREE_ENDPOINT.format(cid=cid, ptid=ptid), action_result, params=params)

        if phantom.is_fail(ret_val):
            self.save_progress('Get process tree Failed')
            return action_result.get_status()

        if response:
            for item in response:
                action_result.add_data(item)
        else:
            return action_result.set_status(phantom.APP_SUCCESS, 'No process tree found')

        self.save_progress('Get process tree Successful')
        message = 'Process tree retrieved'

        summary = action_result.update_summary({})
        summary['total_items'] = len(response)

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_get_events(self, param):
        """ Return events and number of events of a certain type where the value exists in one or more
        of the queried fields from an existing connection.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        event_type = param['event_type']
        if event_type not in EVENT_TYPE_VALUE_LIST:
            return action_result.set_status(
                phantom.APP_ERROR, "Please provide valid input from {} in 'event_type' action parameter".format(EVENT_TYPE_VALUE_LIST))

        ret_val, limit = self._validate_integer(action_result, param.get('limit'), LIMIT_KEY, False)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, offset = self._validate_integer(action_result, param.get('offset'), OFFSET_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        sort = param.get('sort')
        fields = param.get('fields')
        operators = param.get('operators')
        value = param.get('value')
        cid = param['connection_id']

        if not self._is_connection_active(action_result, cid):
            self.save_progress('Inactive or non-existent connection')
            return action_result.get_status()

        params = {}

        if limit:
            params['limit'] = limit

        if sort:
            params['sort'] = sort

        if fields or value or operators:
            if not (fields and value and operators):
                return action_result.set_status(
                    phantom.APP_ERROR, 'fields, operators, and value need to be filled in to query events. Returning all results')
            else:

                filter_type = param.get("filter_type", "all")
                if filter_type and filter_type not in FILTER_TYPE_VALUE_LIST:
                    return action_result.set_status(
                        phantom.APP_ERROR, "Please provide valid input from {} in 'filter_type' action parameter".format(FILTER_TYPE_VALUE_LIST))

                fields = [field.strip() for field in fields.split(',')]
                fields = list(filter(None, fields))

                value = [val.strip() for val in value.split(',')]
                value = list(filter(None, value))

                operators = [operator.strip() for operator in operators.split(',')]
                operators = list(filter(None, operators))

                if not (len(fields) == len(value) and len(value) == len(operators)):
                    return action_result.set_status(phantom.APP_ERROR, "Length of value, fields , and operators must be equal")

                group_list = []

                for i, _filter in enumerate(fields):
                    params["f{}".format(str(i))] = fields[i]
                    params["o{}".format(str(i))] = operators[i]
                    params["v{}".format(str(i))] = value[i]
                    group_list.append(str(i))

                params["gm1"] = filter_type
                params["g1"] = ",".join(group_list)

        ret_val, response = self._make_rest_call_helper(GET_EVENTS_ENDPOINT.format(cid=cid, type=event_type), action_result, params=params)

        if phantom.is_fail(ret_val):
            self.save_progress('Get Events Count Failed')
            return action_result.get_status()

        """
        action_result.update_summary({'event_count': response})

        if limit:
            params['limit'] = limit
        if offset:
            params['offset'] = offset
        if sort:
            params['sort'] = sort

        endpoint = '/plugin/products/trace/conns/{0}/{1}/events'.format(cid, event_type)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=params)
        """

        if phantom.is_fail(ret_val):
            self.save_progress('Get Events Failed')
            return action_result.get_status()

        for event in response:
            action_result.add_data(event)
        action_result.update_summary({'type': event_type})

        # Results will contain 1 more than the limit when there is more data
        if len(response) == limit + 1:
            action_result.update_summary({'More data': True})
        else:
            action_result.update_summary({'More data': False})

        self.save_progress('Get Events Successful')
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_events_summary(self, param):
        """ Return counts of event types and operations from an existing connection.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        cid = param['connection_id']
        event_type = param['event_type']

        if not self._is_connection_active(action_result, cid):
            self.save_progress('Inactive or non-existent connection')
            return action_result.get_status()

        ret_val, response = self._make_rest_call_helper(GET_EVENTS_SUMMARY_ENDPOINT.format(cid=cid, type=event_type), action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('Events Summary Failed')
            return action_result.get_status()

        if not response:
            response = []

        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['total_{}_events_count'.format(event_type)] = response.get('count')

        self.save_progress('Events Summary Successful')
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_files(self, param):
        """ Return list of saved files and number of files.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, response = self._make_rest_call_helper(LIST_FILE_EVIDENCE_ENDPOINT, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('List Files Failed')
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_SUCCESS, 'No results found')

        if 'fileEvidence' in response:
            for evidence_file in response['fileEvidence']:
                action_result.add_data(evidence_file)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        if 'totalCount' in response:
            summary['file_count'] = response['totalCount']
        else:
            summary['file_count'] = 0

        self.save_progress('List Files Successful')
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_save_file(self, param):
        """ Save file from remote computer to Tanium Threat Response.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        cid = param['connection_id']

        if not self._is_connection_active(action_result, cid):
            self.save_progress('Inactive or non-existent connection')
            return action_result.get_status()

        data = {
            'path': param.get('file_path')
        }

        ret_val, response = self._make_rest_call_helper(SAVE_FILE_EVIDENCE_ENDPOINT.format(cid=cid), action_result, json=data, method='post')

        if phantom.is_fail(ret_val):
            self.save_progress('Save File Failed')
            return action_result.get_status()

        self.save_progress('Save File Successful')
        message = 'Save file requested'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_delete_file(self, param):
        """ Delete a downloaded file from Tanium Threat Response.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        file_id = param['file_id']
        ret_val, response = self._make_rest_call_helper(DELETE_FILE_EVIDENCE_ENDPOINT.format(file_id=file_id), action_result, method='delete')

        if phantom.is_fail(ret_val):
            self.save_progress('Delete File Failed')
            return action_result.get_status()

        self.save_progress('Delete File Successful')
        message = 'Delete file requested'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_get_file(self, param):
        """ Download a file from Tanium Threat Response to the Phantom Vault.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        file_id = param["file_id"]
        headers = {'Content-Type': 'application/zip'}

        ret_val, response = self._make_rest_call_helper(DOWNLOAD_FILE_EVIDENCE_ENDPOINT.format(file_id=file_id), action_result, headers=headers)

        if phantom.is_fail(ret_val):
            self.save_progress('Get File Failed')
            return action_result.get_status()

        metadata = {
            'size': len(response.content),
            'contains': [],
            'action': self.get_action_name(),
            'app_run_id': self.get_app_run_id()
        }

        # Get file name from Tanium, if it exists
        ret_val, filename = self._get_filename_from_tanium(action_result, file_id)

        # file is now sent as a zip object - this will make it easier to read
        filename = "{}.zip".format(filename)

        # Save file
        self.send_progress('Saving file to disk')
        try:
            temp_name = self._save_temp_file(response.content)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.debug_print('Error creating file')
            return action_result.set_status(phantom.APP_ERROR, 'Error creating file. {}'.format(err))

        if phantom.is_fail(ret_val) or not filename:
            filename = temp_name.split('/')[-1]

        vault = Vault.add_attachment(temp_name, self.get_container_id(), file_name=filename, metadata=metadata)
        if filename:
            vault['file_name'] = filename

        action_result.add_data(vault)

        self.save_progress('Get File Successful')
        message = 'File downloaded to vault'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_upload_intel_doc(self, param):
        """ Upload intel document to Tanium Threat Response.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        file_name = param.get('file_name')
        data = param.get('intel_doc')
        vault_id = param.get('vault_id')

        if vault_id:
            _, _, vault_info = ph_rules.vault_info(vault_id=vault_id)
            if not file_name and (vault_info and 'name' in vault_info[0]):
                file_name = vault_info[0]['name']
            if 'path' in vault_info[0]:
                data = open(vault_info[0]['path'], 'rb').read()
        else:
            if not (file_name and data):
                return action_result.set_status(phantom.APP_ERROR, 'Error: please provide an intel doc and target file name.')

        headers = {
            'Content-Type': 'application/octet-stream'
        }

        if file_name:
            headers['Content-Disposition'] = "filename={}".format(file_name)

        ret_val, response = self._make_rest_call_helper(UPLOAD_INTEL_DOC_ENDPOINT, action_result, headers=headers, data=data, method='post')

        if phantom.is_fail(ret_val):
            self.save_progress('Upload intel document failed')
            return action_result.get_status()

        action_result.add_data(response)

        self.save_progress('Upload intel document successful')
        message = 'Uploaded intel document to Tanium Threat Response'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_start_quick_scan(self, param):
        """ Scan a computer group for hashes in intel document.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        computer_group_name = param['computer_group_name']
        ret_val, intel_doc_id = self._validate_integer(action_result, param.get('intel_doc_id'), INTEL_DOC_ID_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        endpoint = "{}/{}".format("/api/v2/groups/by-name", computer_group_name)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        response_data = response.get("data")

        if not response_data:
            error_message = "No group exists with name {}. Also, please verify that your \
                    account has sufficient permissions to access the groups".format(
                        computer_group_name)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        computer_group_id = response_data.get("id")

        data = {
            'intelDocId': intel_doc_id,
            'computerGroupId': computer_group_id
        }

        endpoint = '/plugin/products/detect3/api/v1/quick-scans'
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, json=data, method='post')

        if phantom.is_fail(ret_val):
            self.save_progress('Start quick scan failed')
            return action_result.get_status()

        action_result.add_data(response)

        self.save_progress('Start quick scan successful')
        message = 'Started quick scan successfully'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_list_alerts(self, param):
        """ List alerts with optional filtering.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, limit = self._validate_integer(action_result, param["limit"], LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        params = {
            'limit': limit
        }
        try:
            for item in param['query'].split('&'):
                key = item.split('=')[0]
                val = item.split('=')[1]
                try:
                    params[key] = int(val)
                except ValueError:
                    params[key] = val
        except Exception:
            self.debug_print("Unable to parse provided query")
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse provided query")

        ret_val, response = self._make_rest_call_helper(LIST_ALERTS_ENDPOINT, action_result, params=params)

        if phantom.is_fail(ret_val):
            self.save_progress('List alerts failed')
            return action_result.get_status()

        try:
            for alert in response:
                details = json.loads(alert['details'])
                if "fullpath" in details['match']['properties']:
                    alert['path'] = details['match']['properties']['fullpath']
                else:
                    alert['path'] = details['match']['properties']['file']['fullpath']

                alert['event_type'] = details['match']['type']

                if "md5" in details['match']['properties']:
                    md5 = details['match']['properties']['md5']
                else:
                    md5 = details['match']['properties']['file']['md5']
                if md5:
                    alert['md5'] = md5
                sha1 = details['match']['properties']['file'].get('sha1')
                if sha1:
                    alert['sha1'] = sha1
                sha256 = details['match']['properties']['file'].get('sha256')
                if sha256:
                    alert['sha256'] = sha256
                action_result.add_data(alert)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing the response from server. {}".format(err))

        action_result.update_summary({'total_alerts': len(response)})

        self.save_progress('List alerts successful')
        message = 'Listed alerts successfully'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def handle_action(self, param):

        # import web_pdb
        # web_pdb.set_trace()

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print('action_id', action_id)

        # Dictionary mapping each action with its corresponding actions
        supported_actions = {
            'test_connectivity': self._handle_test_connectivity,
            'list_connections': self._handle_list_connections,
            'close_connection': self._handle_close_connection,
            'create_connection': self._handle_create_connection,
            'get_endpoint': self._handle_get_endpoint,
            'delete_connection': self._handle_delete_connection,
            'list_snapshots': self._handle_list_snapshots,
            'create_snapshot': self._handle_create_snapshot,
            'delete_snapshot': self._handle_delete_snapshot,
            'get_process': self._handle_get_process,
            'get_process_tree': self._handle_get_process_tree,
            'get_events': self._handle_get_events,
            'get_events_summary': self._handle_get_events_summary,
            'list_files': self._handle_list_files,
            'save_file': self._handle_save_file,
            'delete_file': self._handle_delete_file,
            'get_file': self._handle_get_file,
            'upload_intel_doc': self._handle_upload_intel_doc,
            'start_quick_scan': self._handle_start_quick_scan,
            'list_alerts': self._handle_list_alerts
        }

        if action_id in supported_actions:
            return supported_actions[action_id](param)
        else:
            return phantom.APP_ERROR
            # raise ValueError('Action {0} is not supported'.format(action_id))

    def initialize(self):

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while fetching the Phantom server's Python major version")

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._base_url = config.get('base_url')

        # removing single occurence of trailing back-slash or forward-slash
        if self._base_url.endswith('/'):
            self._base_url = self._base_url.strip('/').strip('\\')
        elif self._base_url.endswith('\\'):
            self._base_url = self._base_url.strip('\\').strip('/')

        # removing single occurence of leading back-slash or forward-slash
        if self._base_url.startswith('/'):
            self._base_url = self._base_url.strip('/').strip('\\')
        elif self._base_url.startswith('\\'):
            self._base_url = self._base_url.strip('\\').strip('/')

        self._api_token = config.get('api_token')
        if self._api_token:
            self._session_key = self._api_token
        else:
            self._session_key = self._state.get('session_key', '')
            self._username = config.get('username')
            self._password = config.get('password')

        if not self._api_token and not (self._username and self._password):
            return self.set_status(phantom.APP_ERROR, "Please provide either an API token, or username and password credentials")

        self._verify_server_cert = config.get('verify_server_cert', False)

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        # self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import argparse

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass('Password: ')

    if username and password:
        try:
            print('Accessing the Login page')
            r = requests.get("{}login".format(BaseConnector._get_phantom_base_url()), verify=False, timeout=DEFAULT_REQUEST_TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = "{}login".format(BaseConnector._get_phantom_base_url())

            print('Logging into Platform to get the session id')
            r2 = requests.post("{}login".format(BaseConnector._get_phantom_base_url()),
                                   verify=False, data=data, headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print('Unable to get session id from the platform. Error: ' + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = TaniumThreatResponseConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
