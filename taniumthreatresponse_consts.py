# File: taniumthreatresponse_consts.py
#
# Copyright (c) 2020-2021 Splunk Inc.
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
TYPE_ERR_MSG = "Error occurred while connecting to the Tanium Threat Response Server. Please check the asset configuration and|or the action parameters"

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
DSTTYPE_VALUE_LIST = ["computer_name", "ip_address"]
EVENT_TYPE_VALUE_LIST = ["combined", "dns", "driver", "file", "network", "process", "registry", "sid", "image"]
FILTER_TYPE_VALUE_LIST = ["any", "all"]
