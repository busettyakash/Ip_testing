import logging
import json
import os
import re
import time
from typing import List, Dict, Any, Optional
from datetime import datetime

import azure.functions as func
import pytz
from azure.identity import ClientSecretCredential
from azure.mgmt.cosmosdb import CosmosDBManagementClient
from azure.mgmt.cosmosdb.models import IpAddressOrRange, DatabaseAccountUpdateParameters

# ---- Environment Setup ----
def get_env(var_name: str) -> str:
    v = os.getenv(var_name)
    if not v:
        raise EnvironmentError(f"Missing required environment variable: {var_name}")
    return v

TENANT_ID = get_env("TENANT_ID")
CLIENT_ID = get_env("CLIENT_ID")
CLIENT_SECRET = get_env("CLIENT_SECRET")
SUBSCRIPTION_ID = get_env("SUBSCRIPTION_ID")
RESOURCE_GROUP = get_env("RESOURCE_GROUP")
COSMOS_ACCOUNT = get_env("COSMOS_ACCOUNT")

def validate_ip(ip: str) -> bool:
    """Return True if IP string is a valid IPv4 address."""
    pattern = re.compile(
        r'^((25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(25[0-5]|2[0-4]\d|1?\d{1,2})$'
    )
    return bool(pattern.match(ip))

def run_update(new_ips: List[str], branch: Optional[str] = None) -> Dict[str, Any]:
    """
    Add IPs to Cosmos DB firewall rules if valid and not duplicate.
    Returns a result dict with statuses/lists. All exceptions are handled.
    """
    invalid_ips, valid_ips, duplicate_ips, added_ips = [], [], [], []
    for ip in new_ips:
        if not validate_ip(ip):
            logging.error(f"Invalid IP: {ip}")
            invalid_ips.append(ip)
        else:
            valid_ips.append(ip)
    if not valid_ips:
        return {
            "status": "failed",
            "message": "No valid IPs found in input.",
            "valid": valid_ips,
            "invalid": invalid_ips,
            "duplicate": [],
            "added": []
        }
    try:
        credential = ClientSecretCredential(
            tenant_id=TENANT_ID,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET
        )
        cosmos_client = CosmosDBManagementClient(credential, SUBSCRIPTION_ID)
        account = cosmos_client.database_accounts.get(RESOURCE_GROUP, COSMOS_ACCOUNT)
        current_rules = account.ip_rules or []
        existing_ips = [rule.ip_address_or_range for rule in current_rules]

        new_ip_rules = []
        for ip in valid_ips:
            if ip in existing_ips:
                logging.warning(f"Duplicate IP – already exists: {ip}")
                duplicate_ips.append(ip)
                continue
            new_ip_rules.append(IpAddressOrRange(ip_address_or_range=ip))
            logging.info(f"Queued for adding: {ip}")

        if not new_ip_rules:
            return {
                "status": "success",
                "message": "No new IPs to add.",
                "valid": valid_ips,
                "invalid": invalid_ips,
                "duplicate": duplicate_ips,
                "added": []
            }

        update_params = DatabaseAccountUpdateParameters(
            location=account.location,
            locations=account.locations,
            is_virtual_network_filter_enabled=True,
            ip_rules=current_rules + new_ip_rules
        )
        logging.info(f"Updating Cosmos DB with {len(new_ip_rules)} new IP(s)...")

        poller = cosmos_client.database_accounts.begin_update(
            RESOURCE_GROUP, COSMOS_ACCOUNT, update_params
        )
        # Wait for the update to complete (with safety timeout)
        timeout_seconds = 600
        start_time = time.time()
        while not poller.done():
            if time.time() - start_time > timeout_seconds:
                raise TimeoutError("Timed out waiting for Cosmos DB update.")
            logging.info("Cosmos DB update still in progress...")
            time.sleep(30)
        poller.result()
        logging.info("All valid IPs have been added successfully.")
        added_ips = [ip_rule.ip_address_or_range for ip_rule in new_ip_rules]

        return {
            "status": "success",
            "message": f"Added {len(added_ips)} IP(s).",
            "valid": valid_ips,
            "invalid": invalid_ips,
            "duplicate": duplicate_ips,
            "added": added_ips
        }
    except Exception as e:
        logging.exception("Unexpected failure during Cosmos DB update.")
        return {
            "status": "failed",
            "message": f"Update error: {str(e)}",
            "valid": valid_ips,
            "invalid": invalid_ips,
            "duplicate": duplicate_ips,
            "added": added_ips
        }

def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure Function HTTP entry point for Cosmos DB IP firewall update.
    Expects 'ips' (space/comma-separated list) as a request parameter or JSON field.
    """
    logging.info("Processing request for Cosmos DB IP update...")

    try:
        # Parse input IPs (accepts GET params or JSON)
        ips_param = req.params.get("ips")
        branch = req.params.get("branch")
        if not ips_param:
            try:
                req_body = req.get_json()
                ips_param = req_body.get("ips")
                branch = req_body.get("branch", branch)
            except Exception:
                pass

        if not ips_param:
            return func.HttpResponse(
                json.dumps({"status": "failed", "message": "No IPs provided ('ips' param or field required)."}),
                status_code=400,
                mimetype="application/json"
            )
        # Support comma/space separated input, flexible white space
        ip_list = re.split(r"[\s,]+", ips_param.strip())
        ip_list = [ip for ip in ip_list if ip]  # Remove blanks

        result = run_update(ip_list, branch)
        return func.HttpResponse(
            json.dumps(result, indent=2),
            status_code=200 if result.get("status") == "success" else 400,
            mimetype="application/json"
        )
    except Exception as e:
        logging.exception("Unexpected error in main entry point")
        return func.HttpResponse(
            json.dumps({"status": "failed", "message": str(e)}),
            status_code=500,
            mimetype="application/json"
        )
