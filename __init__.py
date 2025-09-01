import logging
import json
import os
import re
import time
from datetime import datetime

import azure.functions as func
import pytz
from azure.identity import ClientSecretCredential
from azure.mgmt.cosmosdb import CosmosDBManagementClient
from azure.mgmt.cosmosdb.models import IpAddressOrRange, DatabaseAccountUpdateParameters

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
SUBSCRIPTION_ID = os.getenv("SUBSCRIPTION_ID")
RESOURCE_GROUP = os.getenv("RESOURCE_GROUP")
COSMOS_ACCOUNT = os.getenv("COSMOS_ACCOUNT")

def validate_ip(ip: str) -> bool:
    pattern = re.compile(
        r'^((25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(25[0-5]|2[0-4]\d|1?\d{1,2})$'
    )
    return bool(pattern.match(ip))

def run_update(new_ips: list, branch: str = None) -> dict:
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
            "message": "No valid IPs found",
            "invalid": invalid_ips,
        }

    try:
        credential = ClientSecretCredential(
            tenant_id=TENANT_ID,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET
        )
        cosmos_client = CosmosDBManagementClient(credential, SUBSCRIPTION_ID)
    except Exception as e:
        return {"status": "failed", "message": f"Auth error – {str(e)}"}

    try:
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
                "message": "No new IPs to add",
                "valid": valid_ips,
                "invalid": invalid_ips,
                "duplicate": duplicate_ips,
                "added": []
            }

        updated_rules = current_rules + new_ip_rules

        logging.info(f"Updating Cosmos DB with {len(new_ip_rules)} new IP(s)...")
        update_params = DatabaseAccountUpdateParameters(
            location=account.location,
            locations=account.locations,
            is_virtual_network_filter_enabled=True,
            ip_rules=updated_rules
        )

        poller = cosmos_client.database_accounts.begin_update(
            RESOURCE_GROUP, COSMOS_ACCOUNT, update_params
        )

        while not poller.done():
            logging.info("Cosmos DB update still in progress...")
            time.sleep(30)

        poller.result()
        logging.info("All valid IPs have been added successfully.")

        for ip_rule in new_ip_rules:
            added_ips.append(ip_rule.ip_address_or_range)

        return {
            "status": "success",
            "valid": valid_ips,
            "invalid": invalid_ips,
            "duplicate": duplicate_ips,
            "added": added_ips
        }

    except Exception as e:
        return {"status": "failed", "message": f"Update error – {str(e)}"}

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing request for Cosmos DB IP update...")

    try:
        ips_param = req.params.get("ips")
        branch = req.params.get("branch")

        if not ips_param:
            return func.HttpResponse(
                json.dumps({"status": "failed", "message": "No IPs provided"}),
                status_code=400,
                mimetype="application/json"
            )

        ip_list = [ip.strip() for ip in ips_param.split() if ip.strip()]
        result = run_update(ip_list, branch)

        return func.HttpResponse(
            json.dumps(result, indent=2),
            status_code=200 if result.get("status") == "success" else 400,
            mimetype="application/json"
        )

    except Exception as e:
        logging.exception("Unexpected error")
        return func.HttpResponse(
            json.dumps({"status": "failed", "message": str(e)}),
            status_code=500,
            mimetype="application/json"
        )
