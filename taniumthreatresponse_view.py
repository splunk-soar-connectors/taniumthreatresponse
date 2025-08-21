# File: taniumthreatresponse_view.py
#
# Copyright (c) 2020-2024 Splunk Inc.
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
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)def get_events(headers, data):


def get_events(headers, data):
    """ Build a list of dictionaries that have the detail and what that detail "contains".

    Args:
        headers (list): Headers for these type of events (Provides the order and expected output)
        data (dict): Event data to lookup

    Returns:
        list: list of dictionary objects that maps the data to what is contained.
    """

    # Map header names to what is contained in each.
    contains_map = {
        'source_addr': ['ip'],
        'destination_ip': ['ip'],
        'local_address': ['ip'],
        'remote_address': ['ip'],
        'username': ['user name'],
        'process_table_id': ['threatresponse process table id'],
        'parent_process_table_id': ['threatresponse process table id'],
        'process_name': ['file path', 'file name'],
        'process_id': ['pid'],
        'process_command_line': ['file name'],
        'file': ['file path'],
        'process_path': ['file path'],
        'path': ['file path'],
        'domain': ['domain'],
        'ImageLoaded': ['file path', 'file name'],
        'Hashes': ['md5'],
        'hash': ['md5'],
        'library_hash': ['md5'],
        'parent_hash': ['md5']
    }

    events = []
    for event in data:
        event_details = []
        for head in headers:
            if "file path" in contains_map.get(head, []):
                event[head] = event.get(head).replace("\\", "\\\\")
            data = event.get(head, None)
            event_details.append({
                'data': data,
                'contains': contains_map.get(head, None) if data else None
            })
        events.append(event_details)

    return events


def display_events(provides, all_app_runs, context):

    # Use this mapping to control what data gets shown in which order for each event type
    headers_map = {
        'combined': [
            'id',
            'pid',
            'process_table_id',
            'type',
            'operation',
            'timestamp',
            'detail'
        ],
        'dns': [
            'id',
            'pid',
            'process_table_id',
            'operation',
            'timestamp',
            'process_path',
            'user_name',
            'group_name',
        ],
        'driver': [
            'id',
            'process_table_id',
            'timestamp',
            'ImageLoaded',
            'Hashes',
            'event_opcode',
            'Signed',
            'Signature',
            'sid',
            'event_task_id',
            'event_record_id',
            'event_id',
        ],
        'file': [
            'id',
            'pid',
            'process_table_id',
            'file',
            'operation',
            'user_name',
            'group_name',
            'details',
            'timestamp'
        ],
        'network': [
            'id',
            'pid',
            'process_table_id',
            'operation',
            'process_path',
            'local_address',
            'local_address_port',
            'remote_address',
            'remote_address_port',
            'user_name',
            'group_name',
            'timestamp'
        ],
        'process': [
            'id',
            'pid',
            'process_table_id',
            'hash_type_name',
            'hash',
            'user_name',
            'group_name',
            'create_time',
            'end_time',
            'process_path',
            'process_command_line',
            'parent_pid',
            'parent_process_table_id',
            'parent_hash',
            'parent_command_line'
        ],
        'registry': [
            'id',
            'pid',
            'process_table_id',
            'key_path',
            'operation',
            'value_name',
            'user_name',
            'group_name',
            'process_path',
            'timestamp'
        ],
        'security': [
            'id',
            'pid',
            'process_table_id',
            'name',
            'string',
            'process_path',
            'task_id',
            'event_id',
            'record_id',
            'user_name',
            'login_user_name',
            'event_name',
            'group_name',
            'properties',
            'property_names',
            'property_values',
            'timestamp'
        ],
        'image': [
            'id',
            'pid',
            'process_table_id',
            'path',
            'hash_type_name',
            'library_hash',
            'user_name',
            'group_name',
            'signature_issuer',
            'signature_subject',
            'signature_status',
            'timestamp'
        ]
    }

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            params = result.get_param()
            headers = headers_map.get(params['event_type'], [])

            results.append({
                'headers': [head.replace('_', ' ') for head in headers],
                'events': get_events(headers, result.get_data()),
                'parameter': result.get_param()
            })

    return 'taniumthreatresponse_display_events.html'


def get_process(headers, data):
    contains_map = {
        'id': ['threatresponse process table id'],
        'process_path': ['file path']
    }

    process_info = []
    for proc in data:
        process_details = []
        for head in headers:
            data = proc.get(head, None)
            process_details.append({
                'data': data,
                'contains': contains_map.get(head, None) if data else None,
            })
        process_info.append(process_details)

    return process_info


def display_process(provides, all_app_runs, context):
    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            headers = ['id', 'detail', 'operation', 'timestamp']

            results.append({
                'headers': [head.replace('_', ' ') for head in headers],
                'process_info': get_process(headers, result.get_data()),
                'parameter': result.get_param()
            })

    return 'taniumthreatresponse_display_process.html'


def display_process_tree(provides, all_app_runs, context):

    context['results'] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            data = result.get_data()
            final_result = []

            for resp in data:
                if resp.get("process_path"):
                    resp["process_path"] = resp.get("process_path").replace("\\", "\\\\")
                final_result.append(resp)

            results.append({
                'data': final_result,
                'parameter': result.get_param(),
                'message': result.get_message()
            })
    return 'taniumthreatresponse_display_process_tree.html'
