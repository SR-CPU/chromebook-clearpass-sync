# Script: Chromebook → ClearPass Sync
# Author: Compugen
# Date: 2025-09-17
# Version: 1.0
# Client: CSSDD

import requests
import logging
import warnings
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

    def _auth_headers(self):
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }

    def token(self):
        url = f"{self.baseurl}/oauth"
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.username,
            "client_secret": self.password,
        }
        headers = {"Content-Type": "application/json"}
        r = self.session.post(url, json=payload, headers=headers,
                              verify=self.ssl_verify, timeout=10)
        r.raise_for_status()
        self.access_token = r.json()["access_token"]

    def endpoint_exists(self, mac):
        url = f"{self.baseurl}/endpoint?filter=%7B%22mac_address%22%3A%20%22{mac}%22%7D"
        r = self.session.get(url, headers=self._auth_headers(),
                             verify=self.ssl_verify, timeout=10)
        return r.status_code == 200 and r.json().get("_embedded", {}).get("items")

    def add_endpoint(self, mac):
        url = f"{self.baseurl}/endpoint"
        payload = {
            "mac_address": mac,
            "status": "Known",
            "attributes": {"MDM Enabled": True}
        }
        r = self.session.post(url, json=payload, headers=self._auth_headers(),
                              verify=self.ssl_verify, timeout=10)
        if r.status_code in (200, 201):
            logging.info(f"Endpoint ajouté pour {mac}")
        else:
            logging.error(f"Erreur ajout endpoint {mac}: {r.text}")

# --- GOOGLE WORKSPACE FUNCTIONS ---
def list_chromebooks():
    creds = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES, subject=SUBJECT
    )
    service = build("admin", "directory_v1", credentials=creds)

    results = service.chromeosdevices().list(customer="my_customer", maxResults=100).execute()
    devices = results.get("chromeosdevices", [])

    chromebooks = []
    for device in devices:
        mac = None
        if "networkInterfaces" in device and device["networkInterfaces"]:
            mac = device["networkInterfaces"][0].get("macAddress")
        elif "ethernetMacAddress" in device:
            mac = device["ethernetMacAddress"]
        if mac:
            chromebooks.append(mac.lower())
    return chromebooks

# --- MAIN SCRIPT ---
def main():
    try:
        cppm = CPPM(CLEARPASS_USER, CLEARPASS_PASS, CLEARPASS_IP)
        cppm.token()

        chromebooks = list_chromebooks()
        logging.info(f"{len(chromebooks)} Chromebooks récupérés.")

        # --- MODE TEST : un seul device ---
        devices_to_process = [chromebooks[0]] if chromebooks else []

        # --- MODE PROD : tous les devices ---
        # devices_to_process = chromebooks

        added, skipped = 0, 0
        for mac in devices_to_process:
            if cppm.endpoint_exists(mac):
                logging.info(f"Endpoint déjà présent pour {mac}")
                skipped += 1
            else:
                cppm.add_endpoint(mac)
                added += 1

        logging.info(f"Résumé: {added} endpoints ajoutés, {skipped} déjà existants.")

    except Exception as e:
        logging.error(f"Erreur: {e}")


if __name__ == "__main__":
    main()
