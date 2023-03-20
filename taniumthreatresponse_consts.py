# File: taniumthreatresponse_consts.py
#
# Copyright (c) 2020-2023 Splunk Inc.
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
# Constants relating to "_get_error_message_from_exception"
ERROR_CODE_MESSAGE = "Error code unavailable"
ERROR_MESSAGE_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
TANIUM_STATE_FILE_CORRUPT_ERROR = "Error occurred while loading the state file due to its unexpected format. \
        Resetting the state file with the default format. Please try again."
TANIUM_SESSION_KEY = "session_key"
TANIUM_SESSION_KEY_IS_ENCRYPTED = "is_encrypted"
TANIUM_ENCRYPTION_ERROR = "Error occurred while encrypting the state file"
TANIUM_DECRYPTION_ERROR = "Error occurred while decrypting the state file"
GET_ENDPOINT_INFO_NEW_CONNECTION_ERROR_MESSAGE = "Get endpoint info for new connection failed"
GET_ENDPOINT_INFO_ERROR_MESSAGE = "Get endpoint info failed or endpoint does not exist"
# Constants relating to "_validate_integer"
VALID_INTEGER_MESSAGE = "Please provide a valid integer value in the {} parameter"
NON_NEGATIVE_INTEGER_MESSAGE = "Please provide a valid non-negative integer value in the {} parameter"
NON_ZERO_POSITIVE_INTEGER_MESSAGE = "Please provide a valid non-zero positive integer value in the {} parameter"
TANIUM_INVALID_INPUT_ERROR = "Please provide valid inputs"
CONNTIMEOUT_KEY = "conntimeout"
PROCESS_TABLE_ID_KEY = "process_table_id"
LIMIT_KEY = "limit"
OFFSET_KEY = "offset"
FILE_ID_KEY = "file_id"
INTEL_DOC_ID_KEY = "intel_doc_id"

# Constants relating to value_list check
DSTTYPE_VALUE_LIST = ["hostname", "ip_address", "client_id"]
CREATE_CONNECTION_REQUIRED_FIELD_LIST = ["hostname", "ip", "clientId", "platform"]
EVENT_TYPE_VALUE_LIST = ["combined", "dns", "driver", "file", "network", "process", "registry", "security", "image"]
FILTER_TYPE_VALUE_LIST = ["any", "all"]
FILE_SORT_TYPE_VALUE_LIST = ["uuid", "hostname", "path", "downloaded", "size"]
SNAPSHOTS_SORT_TYPE_VALUE_LIST = ["uuid", "username", "hostname", "created", "connectionId", "size", "name"]
PROCESS_CONTEXT_VALUE_LIST = ["parent", "node", "siblings", "children"]

# Value list to parameter name mapping
DSTTYPE_PARAMETER_NAME = {
                            "hostname": "hostname",
                            "ip_address": "ip",
                            "client_id": "clientId"
                         }

# API Endpoints
LIST_ALERTS_ENDPOINT = "/plugin/products/threat-response/api/v1/alerts"
GET_ENDPOINT_API_ENDPOINT = "/plugin/products/dec/v1/endpoints"
CREATE_CONNECTION_ENDPOINT = "/plugin/products/threat-response/api/v1/conns/connect"
CLOSE_CONNECTION_ENDPOINT = "/plugin/products/threat-response/api/v1/conns/close/{cid}"
LIST_CONNECTIONS_ENDPOINT = "/plugin/products/threat-response/api/v1/conns"
STATUS_ENDPOINT = "/plugin/products/threat-response/api/v1/status"
CREATE_SNAPSHOT_ENDPOINT = "/plugin/products/threat-response/api/v1/conns/{cid}/snapshot"
DELETE_SNAPSHOT_ENDPOINT = "/plugin/products/threat-response/api/v1/snapshot"
GET_ALL_SNAPSHOTS_ENDPOINT = "/plugin/products/threat-response/api/v1/snapshot"
DELETE_CONNECTION_ENDPOINT = "/plugin/products/threat-response/api/v1/conns/delete/{cid}"
GET_CONNECTION_ENDPOINT = "/plugin/products/threat-response/api/v1/conns/{cid}"
GET_EVENTS_ENDPOINT = "/plugin/products/threat-response/api/v1/conns/{cid}/views/{type}/events"
GET_EVENTS_SUMMARY_ENDPOINT = "/plugin/products/threat-response/api/v1/conns/{cid}/views/{type}/eventsCount"
LIST_FILE_EVIDENCE_ENDPOINT = "/plugin/products/threat-response/api/v1/filedownload"
SAVE_FILE_EVIDENCE_ENDPOINT = "/plugin/products/threat-response/api/v1/conns/{cid}/file"
DELETE_FILE_EVIDENCE_ENDPOINT = "/plugin/products/threat-response/api/v1/filedownload/{file_id}"
GET_FILE_EVIDENCE_ENDPOINT = "/plugin/products/threat-response/api/v1/filedownload/{file_id}"
DOWNLOAD_FILE_EVIDENCE_ENDPOINT = "/plugin/products/threat-response/api/v1/filedownload/data/{file_id}"
DELETE_LOCAL_SNAPSHOT_ENDPOINT = "/plugin/products/threat-response/api/v1/snapshot/{id}"
UPLOAD_INTEL_DOC_ENDPOINT = "/plugin/products/threat-response/api/v1/intels"
GET_PROCESS_DETAILS_ENDPOINT = "/plugin/products/threat-response/api/v1/conns/{cid}/processevents/{ptid}/{type}"
GET_PROCESS_TREE_ENDPOINT = "/plugin/products/threat-response/api/v1/conns/{cid}/processtrees/{ptid}"

DEFAULT_REQUEST_TIMEOUT = 60  # in seconds
