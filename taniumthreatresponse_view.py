# File: taniumthreatresponse_view.py
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
        'username': ['user name'],
        'process_table_id': ['threatresponse process table id'],
        'process_name': ['file path', 'file name'],
        'process_id': ['pid'],
        'process_command_line': ['file name'],
        'file': ['file path'],
        'domain': ['domain'],
        'ImageLoaded': ['file path', 'file name'],
        'Hashes': ['md5']
    }

    events = []
    for event in data:
        event_details = []
        for head in headers:
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
            'type',
            'detail',
            'operation',
            'timestamp',
            'process_path',
            'timestamp_raw',
            'process_table_id'
        ],
        'dns': [
            'id',
            'timestamp',
            'operation',
            'query',
            'response',
            'process_name',
            'process_table_id',
            'process_id',
            'domain',
            'username',
            'timestamp_raw'
        ],
        'driver': [
            'id',
            'timestamp',
            'ImageLoaded',
            'Hashes',
            'event_opcode',
            'process_table_id',
            'Signed',
            'Signature',
            'sid',
            'event_task_id',
            'event_record_id',
            'event_id',
            'timestamp_raw'
        ],
        'file': [
            'id',
            'pid',
            'file',
            'details',
            'operation',
            'timestamp',
            'user_name',
            'group_name',
            'process_path',
            'timestamp_raw',
            'process_table_id',
            'event_operation_id'
        ],
        'network': [
            'id',
            'pid',
            'operation',
            'timestamp',
            'user_name',
            'group_name',
            'process_path',
            'local_address',
            'timestamp_raw',
            'remote_address',
            'process_table_id',
            'event_operation_id',
            'local_address_port',
            'remote_address_port'
        ],
        'process': [
            'id',
            'pid',
            'hash',
            'end_time',
            'exit_code',
            'user_name',
            'group_name',
            'parent_pid',
            'create_time',
            'parent_hash',
            'end_time_raw',
            'process_path',
            'hash_type_name',
            'create_time_raw',
            'process_table_id',
            'parent_command_line',
            'process_command_line',
            'parent_process_table_id'
        ],
        'registry': [
            'id',
            'pid',
            'key_path',
            'operation',
            'timestamp',
            'user_name',
            'group_name',
            'value_name',
            'process_path',
            'timestamp_raw',
            'process_table_id',
            'event_operation_id'
        ],
        'security': [
            'id',
            'pid',
            'name',
            'string',
            'task_id',
            'event_id',
            'record_id',
            'timestamp',
            'user_name',
            'event_name',
            'group_name',
            'properties',
            'process_path',
            'timestamp_raw',
            'property_names',
            'login_user_name',
            'property_values',
            'process_table_id'
        ],
        'image': [
            'id',
            'pid',
            'process_path',
            'path',
            'hash_type_name',
            'library_hash',
            'user_name',
            'group_name',
            'signature_issuer',
            'signature_subject',
            'signature_status',
            'timestamp',
            'timestamp_raw',
            'process_table_id',
        ]
    }

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            params = result.get_param()
            headers = headers_map.get(params['event_type'], [])

            results.append({
                'headers': headers,
                'events': get_events(headers, result.get_data())
            })

    return 'taniumthreatresponse_display_events.html'


def get_process(headers, data):
    contains_map = {
        'id': ['threatresponse process table id']
    }

    process_info = []
    for proc in data:
        process_details = []
        for head in headers:
            data = proc.get(head, None)
            process_details.append({
                'data': data,
                'contains': contains_map.get(head, None) if data else None
            })
        process_info.append(process_details)

    return process_info


def display_process(provides, all_app_runs, context):
    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            headers = ['id', 'type', 'detail', 'operation', 'timestamp', 'timestamp_raw']

            results.append({
                'headers': headers,
                'process_info': get_process(headers, result.get_data())
            })

    return 'taniumthreatresponse_display_process.html'


def display_process_tree(provides, all_app_runs, context):

    context['results'] = results = []
    final_result, t = [], {}

    for summary, action_results in all_app_runs:
        for result in action_results:
            data = result.get_data()
            for index, item in enumerate(data):
                item['children'] = []
                if item['context'] == 'parent':
                    del item['parent_process_table_id']
                    final_result.append(item)
                    # del data(index)
                    t[item['process_table_id']] = final_result[0]

            for item in data:
                if item['context'] != 'parent':
                    if 'children' not in item:
                        item['children'] = []
                    t[item['parent_process_table_id']]['children'].append(item)
                    t[item['process_table_id']] = t[item['parent_process_table_id']]['children'][-1]
                    del t[item['parent_process_table_id']]['children'][-1]['parent_process_table_id']

            results.append({
                'data': final_result,
                'parameter': result.get_param(),
                'message': result.get_message()
            })

    return 'taniumthreatresponse_display_process_tree.html'
