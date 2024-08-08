from flask import Flask, request, jsonify
import requests
from azure.identity import DefaultAzureCredential
from tabulate import tabulate
import ipaddress
import threading

app = Flask(__name__)

# Replace these values with your own
workspace_id = "subscriptions/3846cb0f-4afa-47ee-8ea4-1c8449c8c8d9/resourcegroups/functionapptostorageflow/providers/microsoft.operationalinsights/workspaces/nsplog"
uri_discovery = "https://management.azure.com/subscriptions/3846cb0f-4afa-47ee-8ea4-1c8449c8c8d9/providers/Microsoft.Network/locations/ukwest/serviceTagDetails?api-version=2021-03-01"
service_tags_map = {}

def get_service_tags(uri_discovery, token):
    #credential = DefaultAzureCredential()
    #token = credential.get_token("https://management.azure.com/.default")
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

def periodic_refresh_service_tags_cache():
    # Your task logic here
    print("periodic_refresh_service_tags_cache")
    refresh_service_tags_cache()

    # Schedule the next call
    threading.Timer(60, periodic_refresh_service_tags_cache).start()  # Call every 60 seconds

def refresh_service_tags_cache(token):
    service_tags = get_service_tags(uri_discovery, token)
    values = service_tags['value']

    for value in values:
        service_tags_map[value['name']] = value['properties']['addressPrefixes']
    print("Total in discovery:", len(values), "Total in dict:", len(service_tags_map))

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
    access_token = request.headers.get('Authorization-la')
    discovery_access_token = request.headers.get('Authorization-discovery') 

    if not access_token or not access_token.startswith('Bearer ') or not discovery_access_token or not discovery_access_token.startswith('Bearer '):
        return jsonify({'error': 'Authorization token is missing or invalid'}), 401

    access_token = access_token[len('Bearer '):]  # Remove 'Bearer ' prefix
    discovery_access_token = discovery_access_token[len('Bearer '):]
    request_data = request.json
    refresh_service_tags_cache(discovery_access_token)
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
        print(suggestions)
        return jsonify(suggestions)
    else:
        return jsonify({'error': response.text}), response.status_code

# Main script
if __name__ == "__main__":
    #threading.Timer(0, periodic_refresh_service_tags_cache).start()
    app.run(debug=True)
