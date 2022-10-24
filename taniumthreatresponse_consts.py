# File: taniumthreatresponse_consts.py
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
# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Tanium Threat Response Server. \
        Please check the asset configuration and|or the action parameters"
GET_ENDPOINT_INFO_NEW_CONNECTION_ERROR_MSG = "Get endpoint info for new connection failed"
GET_ENDPOINT_INFO_ERROR_MSG = "Get endpoint info failed or endpoint does not exist"
# Constants relating to '_validate_integer'
VALID_INTEGER_MSG = "Please provide a valid integer value in the {}"
NON_NEGATIVE_INTEGER_MSG = "Please provide a valid non-negative integer value in the {}"
NON_ZERO_POSITIVE_INTEGER_MSG = "Please provide a valid non-zero positive integer value in the {}"
CONNTIMEOUT_KEY = "'conntimeout' action parameter"
PROCESS_TABLE_ID_KEY = "'process_table_id' action parameter"
LIMIT_KEY = "'limit' action parameter"
OFFSET_KEY = "'offset' action parameter"
FILE_ID_KEY = "'file_id' action parameter"
INTEL_DOC_ID_KEY = "'intel_doc_id' action parameter"

# Constants relating to value_list check
DSTTYPE_VALUE_LIST = ["hostname", "ip_address", "client_id"]
CREATE_CONNECTION_REQUIRED_FIELD_LIST = ["hostname", "ip", "clientId", "platform"]
EVENT_TYPE_VALUE_LIST = ["combined", "dns", "driver", "file", "network", "process", "registry", "security", "image"]
FILTER_TYPE_VALUE_LIST = ["any", "all"]

# Value list to parameter name mapping
DSTTYPE_PARAMETER_NAME = {
                            "hostname": "hostname",
                            "ip_address": "ip",
                            "client_id": "clientId"
                         }

# API Endpoints
LIST_ALERTS_ENDPOINT = '/plugin/products/detect3/api/v1/alerts'
GET_ENDPOINT_API_ENDPOINT = '/plugin/products/dec/v1/endpoints'
CREATE_CONNECTION_ENDPOINT = '/plugin/products/threat-response/api/v1/conns/connect'
CLOSE_CONNECTION_ENDPOINT = '/plugin/products/threat-response/api/v1/conns/close/{cid}'
LIST_CONNECTIONS_ENDPOINT = '/plugin/products/threat-response/api/v1/conns'
STATUS_ENDPOINT = '/plugin/products/threat-response/api/v1/status'
CREATE_SNAPSHOT_ENDPOINT = '/plugin/products/threat-response/api/v1/conns/{cid}/snapshot'
DELETE_SNAPSHOT_ENDPOINT = '/plugin/products/threat-response/api/v1/snapshot'
GET_ALL_SNAPSHOTS_ENDPOINT = '/plugin/products/threat-response/api/v1/snapshot'
DELETE_CONNECTION_ENDPOINT = '/plugin/products/threat-response/api/v1/conns/delete/{cid}'
GET_CONNECTION_ENDPOINT = '/plugin/products/threat-response/api/v1/conns/{cid}'
GET_EVENTS_ENDPOINT = '/plugin/products/threat-response/api/v1/conns/{cid}/views/{type}/events'
GET_EVENTS_SUMMARY_ENDPOINT = '/plugin/products/threat-response/api/v1/conns/{cid}/views/{type}/eventsCount'
LIST_FILE_EVIDENCE_ENDPOINT = '/plugin/products/threat-response/api/v1/filedownload'
SAVE_FILE_EVIDENCE_ENDPOINT = '/plugin/products/threat-response/api/v1/conns/{cid}/file'
DELETE_FILE_EVIDENCE_ENDPOINT = '/plugin/products/threat-response/api/v1/filedownload/{file_id}'
GET_FILE_EVIDENCE_ENDPOINT = '/plugin/products/threat-response/api/v1/filedownload/{file_id}'
DOWNLOAD_FILE_EVIDENCE_ENDPOINT = '/plugin/products/threat-response/api/v1/filedownload/data/{file_id}'
DELETE_LOCAL_SNAPSHOT_ENDPOINT = '/plugin/products/threat-response/api/v1/snapshot/{id}'
UPLOAD_INTEL_DOC_ENDPOINT = '/plugin/products/detect3/api/v1/intels'
GET_PROCESS_DETAILS_ENDPOINT = '/plugin/products/threat-response/api/v1/conns/{cid}/processevents/{ptid}/{type}'
GET_PROCESS_TREE_ENDPOINT = '/plugin/products/threat-response/api/v1/conns/{cid}/processtrees/{ptid}'

# Connection Status
CONNECTION_STATUS = {'connected': 'active', 'disconnected': 'inactive'}
DEFAULT_REQUEST_TIMEOUT = 60  # in seconds
