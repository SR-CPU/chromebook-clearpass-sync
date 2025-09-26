# File: main_sync_workspace_cppm.py
# Script: Chromebook → ClearPass Sync
# Author: [Compugen]
# Date: 2025-09-24
# Version: 1.3 (Ajout de la mise à jour MDM Enabled si manquant)
# Client: XXXXX

import requests
import logging
import warnings
import os
from googleapiclient.discovery import build
from google.oauth2 import service_account
from config import (
    SERVICE_ACCOUNT_FILE,
    SUBJECT,
    SCOPES,
    CLEARPASS_IP,
    CLEARPASS_USER,
    CLEARPASS_PASS,
    LOG_FILE,
)

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

logging.basicConfig(
    filename=LOG_FILE,
    format="%(asctime)s %(levelname)s: %(message)s",
    level=logging.INFO
)

# --- CLEARPASS API CLASS ---
class CPPM:
    def __init__(self, username, password, ip, ssl_verify=False):
        self.username = username
        self.password = password
        self.ip = ip
        self.ssl_verify = ssl_verify
        self.session = requests.Session()
        self.baseurl = f"https://{ip}/api"
        self.access_token = None

    def token(self):
        url = f"{self.baseurl}/oauth"
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.username,
            "client_secret": self.password,
        }
        headers = {"Content-Type": "application/json"}
        r = self.session.post(url, json=payload, headers=headers, verify=self.ssl_verify, timeout=20)
        r.raise_for_status()
        self.access_token = r.json()["access_token"]

    def endpoint_exists(self, mac):
        url = f"{self.baseurl}/endpoint?filter=%7B%22mac_address%22%3A%20%22{mac}%22%7D"
        headers = {"Authorization": f"Bearer {self.access_token}"}
        r = self.session.get(url, headers=headers, verify=self.ssl_verify, timeout=15)
        if r.status_code == 200:
            items = r.json().get("_embedded", {}).get("items", [])
            if items:
                return items[0]  # retourne les détails de l’endpoint
        return None

    def add_endpoint(self, mac):
        url = f"{self.baseurl}/endpoint"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        payload = {
            "mac_address": mac,
            "status": "Known",
            "attributes": {"MDM Enabled": True}
        }
        r = self.session.post(url, json=payload, headers=headers, verify=self.ssl_verify, timeout=20)
        if r.status_code in (200, 201):
            return True
        else:
            logging.error(f"❌ Erreur ajout endpoint {mac}: {r.text}")
            return False

    def update_endpoint(self, endpoint_id, mac):
        url = f"{self.baseurl}/endpoint/{endpoint_id}"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        payload = {
            "status": "Known",
            "attributes": {"MDM Enabled": True}
        }
        r = self.session.patch(url, json=payload, headers=headers, verify=self.ssl_verify, timeout=20)
        if r.status_code == 200:
            logging.info(f"♻️ Endpoint {mac} mis à jour avec MDM Enabled.")
            return True
        else:
            logging.error(f"❌ Erreur update endpoint {mac}: {r.text}")
            return False

# --- GOOGLE WORKSPACE FUNCTIONS ---
def list_chromebooks():
    creds = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES, subject=SUBJECT
    )
    service = build("admin", "directory_v1", credentials=creds)

    page_token = None
    macs = []

    while True:
        results = service.chromeosdevices().list(
            customerId="my_customer",
            maxResults=500,
            projection="FULL",
            fields="chromeosdevices(deviceId,ethernetMacAddress,macAddress),nextPageToken",
            pageToken=page_token
        ).execute()

        for dev in results.get("chromeosdevices", []):
            if "ethernetMacAddress" in dev:
                macs.append(dev["ethernetMacAddress"].lower())
            if "macAddress" in dev:
                macs.append(dev["macAddress"].lower())

        page_token = results.get("nextPageToken")
        if not page_token:
            break

    return macs

# --- MAIN SCRIPT ---
def main():
    device_count_file = "device_count.txt"
    last_known_count = 0

    if os.path.exists(device_count_file):
        try:
            with open(device_count_file, "r") as f:
                last_known_count = int(f.read().strip())
        except (IOError, ValueError):
            logging.warning(f"⚠️ Impossible de lire ou de convertir {device_count_file}. La synchronisation sera exécutée.")
            last_known_count = 0

    try:
        chromebooks = list_chromebooks()
        current_count = len(chromebooks)

        if current_count == last_known_count:
            logging.info(f"✅ Nombre d'appareils ({current_count}) inchangé. Aucune synchronisation nécessaire.")
            return

        logging.info(f"🔄 Changement détecté : {last_known_count} → {current_count}. Synchronisation en cours...")

        cppm = CPPM(CLEARPASS_USER, CLEARPASS_PASS, CLEARPASS_IP)
        cppm.token()

        added, skipped, updated, errors = 0, 0, 0, 0
        for mac in chromebooks:
            try:
                endpoint = cppm.endpoint_exists(mac)
                if endpoint:
                    attrs = endpoint.get("attributes", {})
                    endpoint_id = endpoint.get("id")
                    if not attrs.get("MDM Enabled"):
                        if cppm.update_endpoint(endpoint_id, mac):
                            updated += 1
                        else:
                            errors += 1
                    else:
                        skipped += 1
                else:
                    if cppm.add_endpoint(mac):
                        added += 1
                    else:
                        errors += 1
            except Exception as err:
                logging.error(f"❌ Erreur traitement {mac}: {err}")
                errors += 1

        logging.info("=== Résumé du run ===")
        logging.info(f"📦 Total récupérés : {len(chromebooks)}")
        logging.info(f"✅ Endpoints ajoutés : {added}")
        logging.info(f"♻️ Endpoints mis à jour : {updated}")
        logging.info(f"⏭️ Déjà conformes : {skipped}")
        logging.info(f"❌ Erreurs : {errors}")
        logging.info("======================")
        
        with open(device_count_file, "w") as f:
            f.write(str(current_count))
            logging.info(f"✅ Nouveau nombre d'appareils ({current_count}) sauvegardé.")

    except Exception as e:
        logging.error(f"Erreur critique: {e}")


if __name__ == "__main__":
    main()
