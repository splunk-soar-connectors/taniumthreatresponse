[comment]: # "Auto-generated SOAR connector documentation"
# Tanium Threat Response

Publisher: Splunk Community  
Connector Version: 1\.0\.25  
Product Vendor: Tanium  
Product Name: Threat Response  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.9\.39220  

This app supports various generic and investigate actions on Tanium Threat Response

[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2020-2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
# Tanium Threat Response Typical Usage Example

To get the information from Tanium Threat Response, you will need to follow a certain flow of
actions to get what you want. First, you will need to run a search to find the computer that Threat
Response can interact with. To get that you can run the `     list computers    ` action to search
through the computers that are connected to Threat Response. You will get back the top 10 computers
that match a search query, so being as specific as possible would be better.

Once you find the computer that you want to collect information from, you need to create a
connection using the `     create connection    ` action, where the name returned from the
`     list computers    ` is used. Otherwise, the connection may take a while and fail. This action
only sends the request to create the connection and will not return the status of that connection.

You can then test to see if your connection was made by running `     get connection    ` . It will
list the status of all the current connections. An **active** status means you can run the other
actions to get information that you may need. Live connections will timeout and need to be recreated
in those cases. Connections to snapshots will stay open and should be closed after everything is
completed.

You can get the list of all the snapshots by running the `     list snapshots    ` action. It will
list all the snapshots, i.e., the snapshot files that are uploaded manually and the snapshots that
are captured through Tanium UI. The `     list local snapshots    ` action lists only those
snapshots which are captured through Tanium UI. Also, the endpoint used in the
`     list local snapshots    ` action will be deprecated in the future so we would suggest you use
the `     list snapshots    ` action instead of the `     list local snapshots    ` action.

To delete a snapshot, you can run the `     delete snapshot    ` action by providing the **host**
and the **filename** . The `     delete local snapshot    ` action does not work as per the
expectation, as the status of the deleted snapshot does not get reflected on the UI. Hence, we would
suggest you use the `     delete snapshot    ` action instead of the
`     delete local snapshot    ` action.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Threat Response asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  required  | string | Tanium Threat Response URL \(e\.g\., https\://tanium\.example\.com\)
**verify\_server\_cert** |  optional  | boolean | Verify Server Certificate
**username** |  required  | string | Username
**password** |  required  | password | Password

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[list computers](#action-list-computers) - Get top 10 suggestions for computers where name or IP contains <name>  
[initialize computers list](#action-initialize-computers-list) - Start background question for computers list  
[list connections](#action-list-connections) - Get a list of connections  
[create connection](#action-create-connection) - Create a new local or remote connection  
[get connection](#action-get-connection) - Gets connection information  
[delete connection](#action-delete-connection) - Deletes connection  
[list local snapshots](#action-list-local-snapshots) - Get a list of local snapshots  
[create snapshot](#action-create-snapshot) - Capture a new snapshot  
[delete local snapshot](#action-delete-local-snapshot) - Delete a local snapshot  
[list snapshots](#action-list-snapshots) - Get a list of all the snapshots  
[delete snapshot](#action-delete-snapshot) - Delete a snapshot  
[get process](#action-get-process) - Get information for a process  
[get process timeline](#action-get-process-timeline) - Get process timeline  
[get process tree](#action-get-process-tree) - Get process tree for a process instance  
[get parent process tree](#action-get-parent-process-tree) - Get parent process tree for a process instance  
[get children process tree](#action-get-children-process-tree) - Get children process tree for a process instance  
[get events](#action-get-events) - Build a query to get events of a certain type from a connection  
[get events summary](#action-get-events-summary) - Returns counts of each type of event  
[list files](#action-list-files) - List downloaded files in Tanium Threat Response  
[save file](#action-save-file) - Save a file from a remote connection to Tanium Threat Response  
[delete file](#action-delete-file) - Delete a downloaded file from Tanium Threat Response  
[get file](#action-get-file) - Download a file from Tanium Threat Response to the Phantom Vault  
[upload intel doc](#action-upload-intel-doc) - Upload intel document to Tanium Threat Response  
[start quick scan](#action-start-quick-scan) - Scan a computer group for hashes in intel document  
[list alerts](#action-list-alerts) - List alerts with optional filtering  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list computers'
Get top 10 suggestions for computers where name or IP contains <name>

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  optional  | Computer name or IP \(partial allowed\) | string |  `host name`  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.name | string |  `host name`  `ip` 
action\_result\.data\.\*\.name | string |  `host name`  `ip` 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.summary\.total\_results | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'initialize computers list'
Start background question for computers list

Type: **generic**  
Read only: **False**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list connections'
Get a list of connections

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.info\.createTime | string | 
action\_result\.data\.\*\.info\.dst | string |  `ip`  `host name` 
action\_result\.data\.\*\.info\.dstType | string | 
action\_result\.data\.\*\.info\.initTime | string | 
action\_result\.data\.\*\.info\.remote | boolean | 
action\_result\.data\.\*\.info\.state | string | 
action\_result\.data\.\*\.lastUpdate | numeric | 
action\_result\.data\.\*\.name | string |  `threatresponse connection id` 
action\_result\.data\.\*\.wasConnected | boolean | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.summary\.active\_connections | numeric | 
action\_result\.summary\.total\_connections | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create connection'
Create a new local or remote connection

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**dst** |  required  | Computer name or IP address | string |  `ip`  `host name` 
**dsttype** |  required  | Type of destination | string | 
**remote** |  optional  | True if remote connection | boolean | 
**conntimeout** |  optional  | Minutes until connection times out \(default is 5 minutes\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.conntimeout | numeric | 
action\_result\.parameter\.dst | string |  `ip`  `host name` 
action\_result\.parameter\.dsttype | string | 
action\_result\.parameter\.remote | boolean | 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get connection'
Gets connection information

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**connection\_id** |  required  | Connection ID | string |  `threatresponse connection id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.connection\_id | string |  `threatresponse connection id` 
action\_result\.data\.\*\.createTime | string | 
action\_result\.data\.\*\.dst | string |  `ip`  `host name` 
action\_result\.data\.\*\.dstType | string | 
action\_result\.data\.\*\.name | string |  `host name`  `ip`  `threatresponse connection id` 
action\_result\.data\.\*\.remote | boolean | 
action\_result\.data\.\*\.state | string | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete connection'
Deletes connection

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**connection\_id** |  required  | Connection ID | string |  `threatresponse connection id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.connection\_id | string |  `threatresponse connection id` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list local snapshots'
Get a list of local snapshots

Type: **investigate**  
Read only: **True**

This action will fetch only those snapshots which are captured through Tanium UI\. The API endpoint used for this action will be deprecated soon so it is suggested to use the 'list snapshot' action\.

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.bytesReceived | string | 
action\_result\.data\.\*\.connection\_id | string |  `threatresponse connection id` 
action\_result\.data\.\*\.snapshot | string |  `threatresponse snapshot id` 
action\_result\.data\.\*\.started | string | 
action\_result\.data\.\*\.state | string | 
action\_result\.data\.\*\.totalBytes | string | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.summary\.total\_snapshots | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create snapshot'
Capture a new snapshot

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**connection\_id** |  required  | Connection ID | string |  `threatresponse connection id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.connection\_id | string |  `threatresponse connection id` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete local snapshot'
Delete a local snapshot

Type: **generic**  
Read only: **False**

The status of the snapshot deleted using this action may not reflect in the Tanium UI\. Also, the API endpoint for this action will be deprecated soon so it is suggested to use the 'delete snapshot' action\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**connection\_id** |  required  | Connection ID | string |  `threatresponse connection id` 
**snapshot** |  required  | Snapshot ID | string |  `threatresponse snapshot id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.connection\_id | string |  `threatresponse connection id` 
action\_result\.parameter\.snapshot | string |  `threatresponse snapshot id` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list snapshots'
Get a list of all the snapshots

Type: **investigate**  
Read only: **True**

This action will fetch all the screenshots that are available on the Tanium Server, i\.e\., the snapshot files that are uploaded manually and the snapshots that are captured through Tanium UI\.

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.host | string |  `host name`  `ip`  `threatresponse connection id` 
action\_result\.data\.\*\.name | string |  `file name` 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.summary\.total\_snapshots | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete snapshot'
Delete a snapshot

Type: **generic**  
Read only: **False**

This action can be used to delete the snapshots that are uploaded manually and the snapshots that are captured through Tanium UI\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**host** |  required  | Connection ID/Directory | string |  `threatresponse connection id`  `host name` 
**filename** |  required  | File name | string |  `file name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.host | string |  `threatresponse connection id`  `host name` 
action\_result\.parameter\.filename | string |  `file name` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get process'
Get information for a process

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**connection\_id** |  required  | Connection ID | string |  `threatresponse connection id` 
**process\_table\_id** |  required  | Process Table ID | numeric |  `threatresponse process table id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.connection\_id | string |  `threatresponse connection id` 
action\_result\.parameter\.process\_table\_id | numeric |  `threatresponse process table id` 
action\_result\.data\.\*\.create\_time | string | 
action\_result\.data\.\*\.create\_time\_raw | numeric | 
action\_result\.data\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.end\_time | string | 
action\_result\.data\.\*\.end\_time\_raw | numeric | 
action\_result\.data\.\*\.exit\_code | numeric | 
action\_result\.data\.\*\.process\_id | numeric | 
action\_result\.data\.\*\.process\_name | string | 
action\_result\.data\.\*\.process\_table\_id | numeric | 
action\_result\.data\.\*\.sid | string | 
action\_result\.data\.\*\.username | string |  `user name` 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get process timeline'
Get process timeline

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**connection\_id** |  required  | Connection ID | string |  `threatresponse connection id` 
**process\_table\_id** |  required  | Process Table ID | numeric |  `threatresponse process table id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.connection\_id | string |  `threatresponse connection id` 
action\_result\.parameter\.process\_table\_id | numeric |  `threatresponse process table id` 
action\_result\.data\.\*\.date | string | 
action\_result\.data\.\*\.event | string |  `file name` 
action\_result\.data\.\*\.isodate | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get process tree'
Get process tree for a process instance

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**connection\_id** |  required  | Connection ID | string |  `threatresponse connection id` 
**process\_table\_id** |  required  | Process Table ID | numeric |  `threatresponse process table id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.connection\_id | string |  `threatresponse connection id` 
action\_result\.parameter\.process\_table\_id | numeric |  `threatresponse process table id` 
action\_result\.data\.\*\.children\.\*\.id | numeric | 
action\_result\.data\.\*\.children\.\*\.name | string | 
action\_result\.data\.\*\.children\.\*\.parent | string | 
action\_result\.data\.\*\.children\.\*\.pid | numeric |  `pid` 
action\_result\.data\.\*\.children\.\*\.ptid | numeric |  `threatresponse process table id` 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.parent | string | 
action\_result\.data\.\*\.pid | numeric |  `pid` 
action\_result\.data\.\*\.ptid | numeric |  `threatresponse process table id` 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get parent process tree'
Get parent process tree for a process instance

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**connection\_id** |  required  | Connection ID | string |  `threatresponse connection id` 
**process\_table\_id** |  required  | Process Table ID | numeric |  `threatresponse process table id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.connection\_id | string |  `threatresponse connection id` 
action\_result\.parameter\.process\_table\_id | numeric |  `threatresponse process table id` 
action\_result\.data\.\*\.children\.\*\.id | numeric | 
action\_result\.data\.\*\.children\.\*\.name | string | 
action\_result\.data\.\*\.children\.\*\.parent | string | 
action\_result\.data\.\*\.children\.\*\.pid | numeric |  `pid` 
action\_result\.data\.\*\.children\.\*\.ptid | numeric |  `threatresponse process table id` 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.parent | string | 
action\_result\.data\.\*\.pid | numeric |  `pid` 
action\_result\.data\.\*\.ptid | numeric |  `threatresponse process table id` 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get children process tree'
Get children process tree for a process instance

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**connection\_id** |  required  | Connection ID | string |  `threatresponse connection id` 
**process\_table\_id** |  required  | Process Table ID | numeric |  `threatresponse process table id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.connection\_id | string |  `threatresponse connection id` 
action\_result\.parameter\.process\_table\_id | numeric |  `threatresponse process table id` 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.name | string |  `file name` 
action\_result\.data\.\*\.parent | string | 
action\_result\.data\.\*\.pid | numeric |  `pid` 
action\_result\.data\.\*\.ptid | numeric |  `threatresponse process table id` 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get events'
Build a query to get events of a certain type from a connection

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**connection\_id** |  required  | Connection ID | string |  `threatresponse connection id` 
**event\_type** |  required  | Type of event | string | 
**limit** |  optional  | Maximum number of results to return | numeric | 
**offset** |  optional  | Offset of the start of results | numeric | 
**sort** |  optional  | Comma\-separated list of fields to sort on \(prefixed by \- for descending and ordered by priority left to right\) | string | 
**fields** |  optional  | Comma\-separated list of fields to search on | string | 
**value** |  optional  | Comma\-separated list of values to search | string | 
**operators** |  optional  | Comma\-separated list of operators to apply between the fields and the values | string | 
**filter\_type** |  optional  | Operator to be applied between filters | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.connection\_id | string |  `threatresponse connection id` 
action\_result\.parameter\.event\_type | string | 
action\_result\.parameter\.fields | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.offset | numeric | 
action\_result\.parameter\.sort | string | 
action\_result\.parameter\.value | string | 
action\_result\.parameter\.operators | string | 
action\_result\.parameter\.filter\_type | string | 
action\_result\.data\.\*\.Hashes | string |  `md5` 
action\_result\.data\.\*\.ImageLoaded | string |  `file path`  `file name` 
action\_result\.data\.\*\.Signature | string | 
action\_result\.data\.\*\.Signed | string | 
action\_result\.data\.\*\.create\_time | string | 
action\_result\.data\.\*\.create\_time\_raw | numeric | 
action\_result\.data\.\*\.destination\_addr | string |  `ip` 
action\_result\.data\.\*\.destination\_port | numeric | 
action\_result\.data\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.end\_time | string | 
action\_result\.data\.\*\.end\_time\_raw | numeric | 
action\_result\.data\.\*\.event\_id | string | 
action\_result\.data\.\*\.event\_opcode | string | 
action\_result\.data\.\*\.event\_record\_id | string | 
action\_result\.data\.\*\.event\_task\_id | numeric | 
action\_result\.data\.\*\.exit\_code | numeric | 
action\_result\.data\.\*\.file | string |  `file path` 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.im\_cares | numeric | 
action\_result\.data\.\*\.key\_path | string | 
action\_result\.data\.\*\.operation | string | 
action\_result\.data\.\*\.process\_command\_line | string |  `file name` 
action\_result\.data\.\*\.process\_id | numeric |  `pid` 
action\_result\.data\.\*\.process\_name | string |  `file name`  `file path` 
action\_result\.data\.\*\.process\_table\_id | numeric |  `threatresponse process table id` 
action\_result\.data\.\*\.query | string | 
action\_result\.data\.\*\.response | string | 
action\_result\.data\.\*\.sid | string | 
action\_result\.data\.\*\.sid\_hash | numeric | 
action\_result\.data\.\*\.source\_addr | string |  `ip` 
action\_result\.data\.\*\.source\_port | numeric | 
action\_result\.data\.\*\.timestamp | string | 
action\_result\.data\.\*\.timestamp\_raw | numeric | 
action\_result\.data\.\*\.username | string |  `user name` 
action\_result\.data\.\*\.value\_name | string | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.summary\.event\_count | string | 
action\_result\.summary\.success | boolean | 
action\_result\.summary\.type | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get events summary'
Returns counts of each type of event

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**connection\_id** |  required  | Connection ID | string |  `threatresponse connection id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.connection\_id | string |  `threatresponse connection id` 
action\_result\.data\.\*\.category | string | 
action\_result\.data\.\*\.count | numeric | 
action\_result\.data\.\*\.operation | string | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.summary\.total\_categories | numeric | 
action\_result\.summary\.total\_events\_count | numeric | 
action\_result\.summary\.total\_events\_operations | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list files'
List downloaded files in Tanium Threat Response

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.comments | string | 
action\_result\.data\.\*\.created | string | 
action\_result\.data\.\*\.created\_by | string | 
action\_result\.data\.\*\.created\_by\_proc | string |  `file name` 
action\_result\.data\.\*\.downloaded | string | 
action\_result\.data\.\*\.hash | string |  `md5` 
action\_result\.data\.\*\.host | string |  `threatresponse connection id` 
action\_result\.data\.\*\.id | numeric |  `threatresponse file id` 
action\_result\.data\.\*\.last\_modified | string | 
action\_result\.data\.\*\.last\_modified\_by | string | 
action\_result\.data\.\*\.last\_modified\_by\_proc | string |  `file path`  `file name` 
action\_result\.data\.\*\.path | string |  `file path` 
action\_result\.data\.\*\.size | numeric |  `file size` 
action\_result\.data\.\*\.spath | string |  `file name` 
action\_result\.data\.\*\.tags | string | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.summary\.file\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'save file'
Save a file from a remote connection to Tanium Threat Response

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**connection\_id** |  required  | Connection ID | string |  `threatresponse connection id` 
**file\_path** |  required  | Location of file on remote computer | string |  `file path` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.connection\_id | string |  `threatresponse connection id` 
action\_result\.parameter\.file\_path | string |  `file path` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete file'
Delete a downloaded file from Tanium Threat Response

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file\_id** |  required  | ID of file on Tanium | numeric |  `threatresponse file id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.file\_id | numeric |  `threatresponse file id` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get file'
Download a file from Tanium Threat Response to the Phantom Vault

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file\_id** |  required  | ID of file on Tanium | numeric |  `threatresponse file id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.file\_id | numeric |  `threatresponse file id` 
action\_result\.data\.\*\.container | numeric | 
action\_result\.data\.\*\.file\_name | string |  `file name` 
action\_result\.data\.\*\.hash | string |  `sha1` 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.message | string | 
action\_result\.data\.\*\.size | numeric |  `file size` 
action\_result\.data\.\*\.succeeded | boolean | 
action\_result\.data\.\*\.vault\_id | string |  `sha1`  `vault id` 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'upload intel doc'
Upload intel document to Tanium Threat Response

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**intel\_doc** |  required  | The text of the intel document | string |  `threatresponse intel doc` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.intel\_doc | string |  `threatresponse intel doc` 
action\_result\.data\.\*\.id | numeric |  `threatresponse intel doc id` 
action\_result\.data\.\*\.revisionId | numeric | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.typeVersion | string | 
action\_result\.data\.\*\.intrinsicId | string | 
action\_result\.data\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.name | string |  `threatresponse intel doc name` 
action\_result\.data\.\*\.description | string |  `threatresponse intel doc description` 
action\_result\.data\.\*\.size | numeric |  `threatresponse intel doc file size` 
action\_result\.data\.\*\.alertCount | numeric | 
action\_result\.data\.\*\.unresolvedAlertCount | numeric | 
action\_result\.data\.\*\.createdAt | string | 
action\_result\.data\.\*\.updatedAt | string | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'start quick scan'
Scan a computer group for hashes in intel document

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**intel\_doc\_id** |  required  | ID of the intel document to scan | numeric |  `threatresponse intel doc id` 
**computer\_group\_name** |  required  | Name of a Tanium computer group to scan | string |  `tanium computer group name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.intel\_doc\_id | numeric |  `threatresponse intel doc id` 
action\_result\.parameter\.computer\_group\_name | string |  `tanium computer group name` 
action\_result\.data\.\*\.intel\_doc\_id | numeric |  `threatresponse intel doc id` 
action\_result\.data\.\*\.computer\_group\_name | string |  `tanium computer group name` 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.revisionId | numeric | 
action\_result\.data\.\*\.alertCount | numeric | 
action\_result\.data\.\*\.createdAt | string | 
action\_result\.data\.\*\.userId | numeric | 
action\_result\.data\.\*\.questionId | numeric | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list alerts'
List alerts with optional filtering

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Query to filter alerts \(e\.g\. 'intelDocId=1&priority=high'\) | string | 
**limit** |  required  | The maximum number of alerts to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.query | string | 
action\_result\.parameter\.limit | string | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.state | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.guid | string | 
action\_result\.data\.\*\.priority | string | 
action\_result\.data\.\*\.severity | string | 
action\_result\.data\.\*\.intelDocId | numeric |  `threatresponse intel doc id` 
action\_result\.data\.\*\.intelDocRevisionId | numeric | 
action\_result\.data\.\*\.scanConfigId | numeric | 
action\_result\.data\.\*\.scanConfigRevisionId | numeric | 
action\_result\.data\.\*\.computerName | string |  `host name` 
action\_result\.data\.\*\.computerIpAddress | string |  `ip` 
action\_result\.data\.\*\.details | string | 
action\_result\.data\.\*\.matchType | string | 
action\_result\.data\.\*\.path | string | 
action\_result\.data\.\*\.event\_type | string | 
action\_result\.data\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.alertedAt | string | 
action\_result\.data\.\*\.createdAt | string | 
action\_result\.data\.\*\.updatedAt | string | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.summary\.total\_alerts | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 