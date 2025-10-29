import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("INSEE_API_KEY")

BASE_URL = "https://api.insee.fr/api-sirene/3.11"
HEADERS = {
    "X-INSEE-Api-Key-Integration": API_KEY,
    "Accept": "application/json"
}

def test_api():
    codes_naf = ["6201Z", "6202A", "6202B"]
    naf_query = " OR ".join([f"activitePrincipaleUniteLegale:{code}" for code in codes_naf])
    params = {
        "q": f"({naf_query})",
        "nombre": 5
    }

    url = f"{BASE_URL}/siren"      # ✔ bonne route pour unités légales
    r = requests.get(url, headers=HEADERS, params=params, timeout=30)
    print("URL finale:", r.url)
    print("Status code:", r.status_code)
    print("Extrait:", r.text[:500])

if __name__ == "__main__":
    assert API_KEY, "INSEE_API_KEY manquant (chargé depuis .env)"
    test_api()
