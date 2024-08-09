from flask import Flask, request, jsonify
import requests
from azure.identity import DefaultAzureCredential
from tabulate import tabulate
import ipaddress
import threading
import paramiko
import json
import logging

app = Flask(__name__)

# Acquire the logger for a library (azure.mgmt.resource in this example)
logging.basicConfig(level=logging.DEBUG)

# Replace these values with your own
workspace_id = "subscriptions/3846cb0f-4afa-47ee-8ea4-1c8449c8c8d9/resourcegroups/functionapptostorageflow/providers/microsoft.operationalinsights/workspaces/nsplog"
uri_discovery = "https://management.azure.com/subscriptions/3846cb0f-4afa-47ee-8ea4-1c8449c8c8d9/providers/Microsoft.Network/locations/ukwest/serviceTagDetails?api-version=2021-03-01"
service_tags_map = {}

def get_service_tags(uri_discovery):
    credential = DefaultAzureCredential()
    token = credential.get_token("https://management.azure.com/.default")
    headers = {
        'Authorization': f'Bearer {token.token}'
    }
    response = requests.get(uri_discovery, headers=headers)
    response.raise_for_status()
    return response.json()

# Function to get the access token from Azure AD
def get_access_token():
    credential = DefaultAzureCredential()
    token = credential.get_token("https://api.loganalytics.io/.default")
    return token.token

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

def refresh_service_tags_cache_nmagent_api():
# VM credentials
    hostname = '10.0.1.4' #Public IP of VM: 20.25.197.116
    port = 22
    username = 'testAdmin'
    passw = 'testPassword@1'

    # Command to execute
    command = 'curl "http://168.63.129.16/machine/plugins/?comp=nmagent&type=SystemTags/list"'

    try:
        # Create an SSH client
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, port, username, passw)
        # Execute the command
        stdin, stdout, stderr = client.exec_command(command)
        # Print the output
        stdout_output = stdout.read().decode()
        # Close the connection
        client.close()
    except Exception as e:
        logging.error(f"Error executing command: {e}")
        return
    try:
        # Parse the JSON string into a Python dictionary
        service_tags_json = json.loads(stdout_output)
    except json.JSONDecodeError as e:
        # Handle the case where `stdout_output` is not valid JSON
        logging.error(f"Error decoding JSON: {e}")
        # Optionally print the raw output for debugging
        logging.error(f"Raw output: {stdout_output}")
        return
    
    version = service_tags_json['version']
    systemTags = service_tags_json['systemTags']

    for systemTag in systemTags:
        service_tags_map[systemTag['name']] = systemTag['ipV4']
        service_tags_map[systemTag['name']].extend(systemTag['ipV6'])

    logging.debug(f"Metering File Version: {version}. Total in discovery: {len(systemTags)}. Total in dict: {len(service_tags_map)}.")

def periodic_refresh_service_tags_cache_discovery_api():
    # Your task logic here
    logging.debug("periodic_refresh_service_tags_cache_discovery_api")
    refresh_service_tags_cache_discovery_api()

    # Schedule the next call
    threading.Timer(60, periodic_refresh_service_tags_cache_discovery_api).start()  # Call every 60 seconds

def refresh_service_tags_cache_discovery_api():
    service_tags = get_service_tags(uri_discovery)
    values = service_tags['value']

    for value in values:
        service_tags_map[value['name']] = value['properties']['addressPrefixes']
    logging.debug(f"Total in discovery: {len(values)}. Total in dict: {len(service_tags_map)}.")

def process_la_result(json_result):    
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
        matched_tag = find_matching_tag(source_ip, service_tags_map)
        suggestions.append(f"Source IP: {source_ip}, Category: {category}, Matched Tag: {matched_tag}")
    return suggestions

@app.route('/query_log_analytics', methods=['POST'])
def query_log_analytics():
    # Extract the authorization token from headers
    access_token = request.headers.get('Authorization')

    if not access_token or not access_token.startswith('Bearer '):
        return jsonify({'error': 'Authorization token is missing or invalid'}), 401

    access_token = access_token[len('Bearer '):]  # Remove 'Bearer ' prefix
    request_data = request.json
    # Prepare the query payload
    query = """NSPAccessLogs
                    | project TimeGenerated, Category, MatchedRule, SourceIpAddress
                    | distinct Category, SourceIpAddress
                    | limit 10"""
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
        response = jsonify(suggestions)
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
    #threading.Timer(0, periodic_refresh_service_tags_cache_nmagent_api).start()
    logging.debug("Call cache refresh.")
    refresh_service_tags_cache_nmagent_api()
    app.run(debug=True)
