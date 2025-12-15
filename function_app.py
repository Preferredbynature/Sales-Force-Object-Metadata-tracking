import azure.functions as func
import datetime
import json
import logging
import os
import requests
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from dotenv import load_dotenv
from azure.storage.blob import BlobServiceClient
from simple_salesforce import Salesforce


OBJECT_APIS = ['AldyTestObject__c']
app = func.FunctionApp()
logger = logging.getLogger("azure.functions")


# ==================== Environment & Config ====================
def is_running_in_azure() -> bool:
    """
    Best-effort check whether code runs inside Azure Functions.
    WEBSITE_INSTANCE_ID exists on Azure Functions runtime; absent locally.
    """
    return bool(os.getenv("WEBSITE_INSTANCE_ID"))


_keyvault_client: Optional[SecretClient] = None


def get_keyvault_client() -> SecretClient:
    """Create (and cache) a Key Vault client."""
    global _keyvault_client
    if _keyvault_client:
        return _keyvault_client

    keyvault_uri = os.getenv("KEYVAULT_URI") or os.getenv("AZURE_KEYVAULT_URI")
    if not keyvault_uri:
        raise RuntimeError("Missing KEYVAULT_URI (or AZURE_KEYVAULT_URI) for Key Vault access")

    credential = DefaultAzureCredential()
    _keyvault_client = SecretClient(vault_url=keyvault_uri, credential=credential)
    return _keyvault_client


def get_secret_value(name: str) -> Optional[str]:
    """
    Resolve a setting/secret.
    - In Azure: try Key Vault first (requires KEYVAULT_URI & managed identity), then env.
    - Local: use env (after load_dotenv).
    """
    keyvault_uri = os.getenv("KEYVAULT_URI")
    if keyvault_uri:
        try:    
            client = get_keyvault_client()
            # Key Vault secrets are stored with hyphens, so we need to replace underscores with hyphens
            return client.get_secret(name.replace("_", "-")).value
        except Exception as e:
            logger.warning(f"Key Vault lookup for '{name}' failed: {e}; falling back to environment variable.")
    _val =  os.getenv(name)
    if _val:
        return _val
    raise Exception(f"Missing required environment variable: {name} in both Key Vault and environment variables") from e

# ==================== Salesforce Metadata ====================
def fetch_snapshot(sf: Salesforce, object_api: str) -> Dict[str, Dict[str, Dict]]:
    """
    Capture field describe + audit info (last modified user/date) for the given object.
    """
    fd_query = (
        "SELECT QualifiedApiName, DataType, Label, "
        "LastModifiedBy.Name, LastModifiedById, LastModifiedDate "
        f"FROM FieldDefinition WHERE EntityDefinition.QualifiedApiName = '{object_api}'"
    )
    fd_records = sf.query_all(fd_query).get("records", [])
    fd_map: Dict[str, Dict] = {}

    for record in fd_records:
        api = record.get("QualifiedApiName")
        if not api:
            continue
        fd_map[api] = {
            "label": record.get("Label"),
            "type": record.get("DataType"),
            "picklist_values": [],
            "last_modified_by": (record.get("LastModifiedBy") or {}).get("Name"),
            "last_modified_by_id": record.get("LastModifiedById"),
            "last_modified_date": record.get("LastModifiedDate"),
        }

    desc = sf.restful(f"sobjects/{object_api}/describe")
    for field in desc.get("fields", []):
        api = field.get("name")
        if not api:
            continue

        pick_values = [
            v.get("value")
            for v in field.get("picklistValues", [])
            if v.get("active") and v.get("value")
        ]

        if api not in fd_map:
            fd_map[api] = {
                "label": field.get("label", api),
                "type": field.get("type", "Unknown"),
                "picklist_values": sorted(pick_values),
                "last_modified_by": None,
                "last_modified_by_id": None,
                "last_modified_date": None,
            }
        else:
            fd_map[api]["label"] = field.get("label", fd_map[api].get("label"))
            fd_map[api]["type"] = field.get("type", fd_map[api].get("type"))
            fd_map[api]["picklist_values"] = sorted(pick_values)
    return {"fields": fd_map}


def diff_lists(old: List[str], new: List[str]) -> Tuple[List[str], List[str]]:
    """Compare two lists and return (removed, added)."""
    removed = sorted(set(old) - set(new))
    added = sorted(set(new) - set(old))
    return list(removed), list(added)


def diff_snapshots(old: Dict, new: Dict) -> Dict[str, List[Dict]]:
    """Compare two snapshots and identify changes."""
    changes = {"added": [], "removed": [], "changed": []}

    old_fields = old.get("fields", {})
    new_fields = new.get("fields", {})

    for field_name in new_fields:
        if field_name not in old_fields:
            meta = new_fields[field_name]
            changes["added"].append(
                {
                    "field": field_name,
                    "label": meta.get("label"),
                    "type": meta.get("type"),
                    "by": meta.get("last_modified_by"),
                    "when": meta.get("last_modified_date"),
                }
            )

    for field_name in old_fields:
        if field_name not in new_fields:
            old_meta = old_fields[field_name]
            changes["removed"].append({
                "field": field_name,
                "when": old_meta.get("last_modified_date")
            })

    for field_name, meta in new_fields.items():
        if field_name not in old_fields:
            continue

        old_meta = old_fields[field_name]
        diffs = {}
        if meta.get("type") != old_meta.get("type"):
            diffs["type"] = (old_meta.get("type"), meta.get("type"))
        if meta.get("label") != old_meta.get("label"):
            diffs["label"] = (old_meta.get("label"), meta.get("label"))

        removed, added = diff_lists(
            old_meta.get("picklist_values", []), meta.get("picklist_values", [])
        )
        if removed or added:
            diffs["picklist_values"] = {"removed": removed, "added": added}

        if diffs:
            changes["changed"].append(
                {
                    "field": field_name,
                    "diffs": diffs,
                    "by": meta.get("last_modified_by"),
                    "when": meta.get("last_modified_date"),
                }
            )
    return changes



# ==================== Blob Storage ====================
def get_blob_client(container_name: str = "salesforce-metadata"):
    """Get Azure Blob Storage client."""
    connection_string = get_secret_value("AzureWebJobsStorage")
    
    blob_service_client = BlobServiceClient.from_connection_string(connection_string)
    container_client = blob_service_client.get_container_client(container_name)
    
    # Create container if it doesn't exist
    try:
        container_client.get_container_properties()
    except:
        container_client = blob_service_client.create_container(container_name)
    
    return container_client


def write_snapshot_to_blob(container_name: str, blob_name: str, snapshot: Dict) -> None:
    """Write snapshot JSON to blob storage."""
    container_client = get_blob_client(container_name)
    blob_client = container_client.get_blob_client(blob_name)
    blob_client.upload_blob(
        json.dumps(snapshot, indent=2, sort_keys=True),
        overwrite=True
    )


def read_snapshot_from_blob(container_name: str, blob_name: str) -> Dict:
    """Read snapshot JSON from blob storage."""
    try:
        container_client = get_blob_client(container_name)
        blob_client = container_client.get_blob_client(blob_name)
        data = blob_client.download_blob().readall().decode("utf-8")
        return json.loads(data)
    except:
        return {"fields": {}}


# ==================== Main Processing ====================
def process_object(sf: Salesforce, object_api: str) -> Dict:
    """Process a single Salesforce object and track changes."""
    logger.info(f"--- {object_api} ---")
    logger.info(f"Fetching metadata for object: {object_api}...")

    snapshot_blob_name = f"snapshot_{object_api}.json"
    container_name = "salesforce-metadata"
    
    current_snapshot = fetch_snapshot(sf, object_api)
    previous_snapshot = read_snapshot_from_blob(container_name, snapshot_blob_name)

    changes = diff_snapshots(previous_snapshot, current_snapshot)

    
    if not any(changes.values()):
        logger.info("No changes detected.")
    
    write_snapshot_to_blob(container_name, snapshot_blob_name, current_snapshot)
    logger.info(f"Snapshot saved to blob: {snapshot_blob_name}")
    
    # Send Teams notification if there are changes
    send_teams_message(changes, object_api)
    
    return {
        "object": object_api,
        "blob": snapshot_blob_name,
        "changes": changes
    }


def format_datetime(datetime_str: str) -> str:
    """Convert ISO datetime string to human-readable format."""
    try:
        # Parse ISO format datetime
        dt = datetime.datetime.fromisoformat(datetime_str.replace('Z', '+00:00'))
        # Format as readable string
        return dt.strftime("%b %d, %Y at %I:%M %p")
    except:
        return datetime_str


def send_teams_message(changes: Dict, object_api: str) -> None:
    """Send detailed change summary to MS Teams. Only send if there are changes."""
    webhook_url = get_secret_value("MS_TEAMS_WEBHOOK_URL")
    # Only send if there are actual changes
    if not any(changes.values()):
        logger.info("No changes detected. Skipping Teams notification.")
        return
    
    sections = []
    theme_color = "0078D4"
    
    # Added fields section
    if changes["added"]:
        added_text = ""
        for f in changes["added"]:
            added_text += f"**{f['field']}**\nType : ({f.get('type', 'Unknown')})\n"
            added_text += f"> 👤 **By:** {f.get('by', 'Unknown')}\n"
            added_text += f"> 📅 **When:** {format_datetime(f.get('when', 'Unknown time'))}\n\n"
        sections.append({
            "activityTitle": "✅ Added Fields",
            "activitySubtitle": f"{len(changes['added'])} new field(s)",
            "text": added_text.strip()
        })
    
    # Removed fields section
    if changes["removed"]:
        removed_text = ""
        for f in changes["removed"]:
            removed_text += f"~~{f['field']}~~\n"
            removed_text += f"> 📅 **It is made at:** {format_datetime(f.get('when', 'Unknown time'))}\n\n"
        sections.append({
            "activityTitle": "❌ Removed Fields",
            "activitySubtitle": f"{len(changes['removed'])} field(s) deleted",
            "text": removed_text.strip()
        })
    
    # Changed fields section
    if changes["changed"]:
        changed_text = ""
        for field in changes["changed"]:
            changed_text += f"**{field['field']}** 🔧\n"
            diffs = field.get("diffs", {})
            if "type" in diffs:
                before, after = diffs["type"]
                changed_text += f"  • Type: `{before}` → `{after}`\n"
            if "label" in diffs:
                before, after = diffs["label"]
                changed_text += f"  • Label: _{before}_ → _{after}_\n"
            if "picklist_values" in diffs:
                pv = diffs["picklist_values"]
                if pv["added"]:
                    changed_text += f"  • ✨ Picklist Added: `{', '.join(pv['added'])}`\n"
                if pv["removed"]:
                    changed_text += f"  • 🗑️ Picklist Removed: `{', '.join(pv['removed'])}`\n"
            changed_text += f"> 👤 **By:** {field.get('by', 'Unknown')}\n"
            if "type" in diffs or "label" in diffs:
                # The changes in picklist values may not correspond to the last modified date
                changed_text += f"> 📅 **When:** {format_datetime(field.get('when', 'Unknown time'))}\n\n"
        sections.append({
            "activityTitle": "🔄 Changed Fields",
            "activitySubtitle": f"{len(changes['changed'])} field(s) modified",
            "text": changed_text.strip()
        })
    
    message = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": f"Salesforce {object_api} metadata changes",
        "themeColor": theme_color,
        "sections": [
            {
                "activityTitle": f"📊 Salesforce Metadata Update: **{object_api}**",
                "activitySubtitle": f"🕐 Metadata check at {datetime.datetime.now().strftime('%b %d, %Y at %I:%M %p UTC')}",
                "markdown": True
            }
        ] + sections
    }
    
    try:
        logger.info(f"Sending Teams notification for {object_api}...")
        response = requests.post(webhook_url, json=message, timeout=10)
        if response.status_code == 200:
            logger.info(f"✅ Teams notification sent successfully for {object_api}.")
        else:
            logger.error(f"❌ Teams webhook returned status code {response.status_code}: {response.text}")
    except requests.exceptions.Timeout as e:
        logger.error(f"⏱️ Teams webhook request timed out: {str(e)}")
    except requests.exceptions.RequestException as e:
        logger.error(f"🌐 Failed to send Teams message: {str(e)}")
    except Exception as e:
        logger.error(f"❗ Unexpected error sending Teams message: {str(e)}")


def main() -> func.HttpResponse:
    try:
        if not is_running_in_azure() and Path(".env").exists():
            load_dotenv(Path(".env"), override=False)
        
        username = get_secret_value("SF_USERNAME")
        password = get_secret_value("SF_PASSWORD")
        security_token = get_secret_value("SF_SECURITY_TOKEN")
        OBJECT_APIS = ['AldyTestObject__c']
        domain = get_secret_value("SF_DOMAIN")
        
        sf = Salesforce(
            username=username, password=password, security_token=security_token, domain=domain
        )
        
        results = []
        for object_api in OBJECT_APIS:
            result = process_object(sf, object_api)
            results.append(result)
        
        logger.info(f"Metadata tracking completed. Processed {len(results)} objects.")
        
        return func.HttpResponse(
            json.dumps({"status": "success"}),
            status_code=200,
            mimetype="application/json"
        )
    
    except Exception as e:
        logger.error(f"Error in metadata tracking: {str(e)}", exc_info=True)
        return func.HttpResponse(
            json.dumps({"status": "error", "message": str(e)}),
            status_code=500,
            mimetype="application/json"
        )

@app.timer_trigger(arg_name="myTimer", schedule="0 0 * * * *")  # Daily at midnight UTC
def salesforce_metadata_tracker(myTimer: func.TimerRequest) -> func.HttpResponse:
    """
    Time-triggered function to track Salesforce object metadata changes.
    Stores snapshots in Azure Blob Storage.
    """
    return main()

@app.function_name(name="salesforce_metadata_tracker_http")
@app.route(
    route="salesforce-metadata",
    methods=["GET"]
)
def salesforce_metadata_tracker_http(req: func.HttpRequest) -> func.HttpResponse:
    """
    HTTP-triggered function to track Salesforce object metadata changes.
    Stores snapshots in Azure Blob Storage.
    """
    return main()