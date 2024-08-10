from flask import Flask, request, jsonify
import requests
from azure.identity import DefaultAzureCredential
from tabulate import tabulate
import ipaddress
import threading
import paramiko
import json
import logging
import pytricia

app = Flask(__name__)

# Acquire the logger for a library (azure.mgmt.resource in this example)
logging.basicConfig(level=logging.DEBUG)

# Replace these values with your own
workspace_id = "subscriptions/3846cb0f-4afa-47ee-8ea4-1c8449c8c8d9/resourcegroups/functionapptostorageflow/providers/microsoft.operationalinsights/workspaces/nsplog"
uri_discovery = "https://management.azure.com/subscriptions/3846cb0f-4afa-47ee-8ea4-1c8449c8c8d9/providers/Microsoft.Network/locations/ukwest/serviceTagDetails?api-version=2021-03-01"

service_tags_map = {}
## Populate prefixes in PyTricia for fast matching.
prefixToTagsTrieCache = pytricia.PyTricia()

def get_service_tags(uri_discovery, token):
    headers = {
        'Authorization': f'Bearer {token}'
    }
    response = requests.get(uri_discovery, headers=headers)
    response.raise_for_status()
    return response.json()

# Function to get the access token from Azure AD
def get_access_token():
    credential = DefaultAzureCredential()
    token = credential.get_token("https://api.loganalytics.io/.default")
    return token.token

def is_valid_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except:
        return False
    return True

# Function to get the longest prefix match
def get_prefix_match(trie, prefix):
    try:
        matched_prefix = trie.get_key(prefix)
        print(f"Prefix: {prefix}")
        if matched_prefix is None:
            return None, None
        return trie[matched_prefix], matched_prefix
    except KeyError:
        return None, None
    
def find_matching_tag_via_trie(ip_str):
    """Find the matching tag for a given IP address."""
    if is_valid_ip(ip_str):
        matched_tags, matched_prefix = get_prefix_match(prefixToTagsTrieCache, ip_str)
        if matched_tags is None:
            return [], '' 
        return matched_tags, matched_prefix
    return [], ''

def find_matching_tag(ip_str, service_tags_map):
    """Find the matching tag for a given IP address."""
    for tag, prefixes in service_tags_map.items():
        for prefix in prefixes:
            if is_ip_in_prefix(ip_str, prefix):
                return tag
    return None

def is_ip_in_prefix(ip_str, prefix_str):
    """Check if an IP address is within a given CIDR prefix."""
    if not ip_str or not prefix_str:
        return False
    ip = ipaddress.ip_address(ip_str)
    network = ipaddress.ip_network(prefix_str, strict=False)
    
    return ip in network

def periodic_refresh_service_tags_cache_nmagent_api():
    # Your task logic here
    logging.debug("periodic_refresh_service_tags_cache_nmagent_api")
    refresh_service_tags_cache_nmagent_api()

    # Schedule the next call
    threading.Timer(60, periodic_refresh_service_tags_cache_nmagent_api).start()  # Call every 60 seconds

def get_service_tags_from_vm():
    logging.debug("get_service_tags_from_vm")
    # VM credentials
    hostname = '10.0.1.4' #Public IP of VM: 20.25.197.116, #Private IP: 10.0.1.4
    port = 22
    username = 'testAdmin'
    passw = 'testPassword@1'

    # Command to execute
    command = 'curl "http://168.63.129.16/machine/plugins/?comp=nmagent&type=SystemTags/list"'

    try:
        logging.debug("Create SSH Client")
        # Create an SSH client
        client = paramiko.SSHClient()
        logging.debug("Set Policy")
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        logging.debug("Connect to VM via Webapp")
        client.connect(hostname, port, username, passw)
        logging.debug("Connection done, send command to execute.")
        # Execute the command
        stdin, stdout, stderr = client.exec_command(command)
        logging.debug(f"Command sent and received response.")
        # Print the output
        stdout_output = stdout.read().decode()
        # Close the connection
        client.close()
    except Exception as e:
        logging.error(f"Error executing command: {e}")
        return False, e
    try:
        # Parse the JSON string into a Python dictionary
        service_tags_json = json.loads(stdout_output)
    except json.JSONDecodeError as e:
        # Handle the case where `stdout_output` is not valid JSON
        logging.error(f"Error decoding JSON: {e}")
        # Optionally print the raw output for debugging
        logging.error(f"Raw output: {stdout_output}")
        return False, e

    return True, service_tags_json

def refresh_service_tags_cache_nmagent_api():
    logging.debug("refresh_service_tags_cache_nmagent_api")
    status, data = get_service_tags_from_vm()
    if status == False:
        return status, data
    
    service_tags_json = data
    version = service_tags_json['version']
    systemTags = service_tags_json['systemTags']

    for systemTag in systemTags:
        service_tags_map[systemTag['name']] = systemTag['ipV4']
        service_tags_map[systemTag['name']].extend(systemTag['ipV6'])

    logging.debug(f"Metering File Version: {version}. Total in discovery: {len(systemTags)}. Total in dict: {len(service_tags_map)}.")
    populate_in_trie(service_tags_map)
    return True, version, len(service_tags_map)

def populate_in_trie(tags_to_prefix_mapping):
    # Invert the dictionary to use prefixes as keys
    for tag, prefixes in tags_to_prefix_mapping.items():
        for prefix in prefixes:
            if prefixToTagsTrieCache.has_key(prefix):
                prefixToTagsTrieCache[prefix].append(tag)
            else:
                prefixToTagsTrieCache.insert(prefix, [tag])
    print("Total Entries in TRIE :", len(prefixToTagsTrieCache))

def periodic_refresh_service_tags_cache_discovery_api():
    # Your task logic here
    logging.debug("periodic_refresh_service_tags_cache_discovery_api")
    refresh_service_tags_cache_discovery_api()

    # Schedule the next call
    threading.Timer(60, periodic_refresh_service_tags_cache_discovery_api).start()  # Call every 60 seconds

def refresh_service_tags_cache_discovery_api():
    credential = DefaultAzureCredential()
    token = credential.get_token("https://management.azure.com/.default")
    service_tags = get_service_tags(uri_discovery, token.token)
    values = service_tags['value']

    for value in values:
        service_tags_map[value['name']] = value['properties']['addressPrefixes']
    logging.debug(f"Total in discovery: {len(values)}. Total in dict: {len(service_tags_map)}.")

def process_la_result(json_result):
    logging.debug(f"process_la_result.")

    # Extract column names and rows from the JSON data
    columns = json_result['tables'][0]['columns']
    column_names = [column['name'] for column in columns]
    rows = json_result['tables'][0]['rows']

    # Step 4: Process and print the results
    # print(tabulate(rows, headers=column_names, tablefmt='grid'))
    suggestions = []
    for row in rows:
        category = row[column_names.index('Category')]
        source_ip = row[column_names.index('SourceIpAddress')]
        matched_tags, prefix = find_matching_tag_via_trie(source_ip)
        suggestion = {}
        suggestion["SourceIP"] = source_ip
        suggestion["Category"] = category
        suggestion["MatchedTags"] = list(set(matched_tags))
        suggestion["MatchedPrefix"] = prefix
        suggestions.append(suggestion)
    
    logging.debug(f"suggestion {len(suggestions)}.")
    return suggestions

@app.route('/refresh_service_tags_cache', methods=['POST'])
def refresh_service_tag_cache():
    logging.debug(f"Called /refresh_service_tags_cache API.")
    status, message1, message2 = refresh_service_tags_cache_nmagent_api()
    if status == True:
        resp = {}
        resp['message'] = 'Service tags cache refreshed successfully'
        resp['Version'] = message1
        resp['TotalTags'] = message2
        return jsonify(resp)
    else:
        return jsonify({'message': message1}), 500


@app.route('/get_service_tags_cache', methods=['POST'])
def get_service_tags_cache():
    logging.debug(f"Called /get_service_tags_cache API.")
    return jsonify(service_tags_map)

@app.route('/get_nmagent_v2_data', methods=['POST'])
def get_nmagent_v2_data():
    logging.debug(f"Called /get_nmagent_v2_data API.")
    status, message1 = get_service_tags_from_vm()
    if (status == False):
        return jsonify({'message': message1}), 500
    return jsonify(message1)

@app.route('/get_discovery_api_data', methods=['POST'])
def get_discovery_api_data():
    logging.debug(f"Called /get_discovery_api_data API.")
    
    # Extract the authorization token from headers
    access_token = request.headers.get('Authorization')

    if not access_token or not access_token.startswith('Bearer '):
        logging.debug(f"No Auth token providing trying generating with env variables.")
        credential = DefaultAzureCredential()
        access_token = credential.get_token("https://management.azure.com/.default")
    else:
        logging.debug(f"Re-using auth token in header.")
        access_token = access_token[len('Bearer '):]  # Remove 'Bearer ' prefix
    return get_service_tags(uri_discovery, access_token)

@app.route('/query_log_analytics', methods=['POST'])
def query_log_analytics():
    logging.debug(f"Called /query_log_analytics API.")
    logging.debug(f"Service tags Dict size {len(service_tags_map)}.")
    if len(service_tags_map)==0:
        logging.debug(f"Calling refreshhhh.")
        refresh_service_tags_cache_nmagent_api()
        logging.debug(f"Refresh doneeee.")


    # Extract the authorization token from headers
    access_token = request.headers.get('Authorization')

    if not access_token or not access_token.startswith('Bearer '):
        return jsonify({'error': 'Authorization token is missing or invalid'}), 401

    access_token = access_token[len('Bearer '):]  # Remove 'Bearer ' prefix
    request_data = request.json
    # Prepare the query payload
    query = """NSPAccessLogs
                    | project TimeGenerated, Category, MatchedRule, SourceIpAddress
                    | distinct Category, SourceIpAddress"""
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    payload = {
        'query': query
    }
    query_url = f"https://api.loganalytics.io/v1{request_data['laWorkspaceId']}/query"
    # Make the request to Azure Log Analytics
    response = requests.post(query_url, headers=headers, json=payload)

    if response.status_code == 200:
        suggestions = process_la_result(response.json())
        response = {}
        response["values"] = suggestions
        logging.debug(f"Response : {response}")
    else:
        response = jsonify({'error': response.text}), response.status_code
    return response

# Example function that triggers a log entry
def example_function():
    print(
        f"Logger enabled for ERROR={logging.isEnabledFor(logging.ERROR)},"
        f"WARNING={logging.isEnabledFor(logging.WARNING)}, "
        f"INFO={logging.isEnabledFor(logging.INFO)}, "
        f"DEBUG={logging.isEnabledFor(logging.DEBUG)}")
    logging.debug("debug: This is a debug message from the Azure SDK")
    logging.info("info: This is a debug message from the Azure SDK")
    logging.error("error: This is a debug message from the Azure SDK")

# Main script
if __name__ == "__main__":
    logging.debug("Call cache refresh.")
    #refresh_service_tags_cache_nmagent_api()
    threading.Timer(0, periodic_refresh_service_tags_cache_nmagent_api).start()
    app.run(debug=True)
