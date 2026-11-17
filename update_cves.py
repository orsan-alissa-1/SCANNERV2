import requests
import sqlite3
import gzip
import json
import os
from datetime import datetime

# NVD feed URL (adjust year if needed)
NVD_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz"

# Paths
os.makedirs("data", exist_ok=True)
DB_PATH = os.path.join("data", "vulnerabilities.db")
JSON_FILE = "nvdcve-2024.json.gz"

def classify_severity(score):
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0.0:
        return "Low"
    else:
        return "Informational"

def extract_vendor_product_version(cpe_uri):
    try:
        parts = cpe_uri.split(":")
        return (
            parts[3] if len(parts) > 3 else "unknown",
            parts[4] if len(parts) > 4 else "unknown",
            parts[5] if len(parts) > 5 else "unknown"
        )
    except Exception as e:
        print(f"⚠️ Failed to parse CPE URI: {cpe_uri} — {e}")
        return "unknown", "unknown", "unknown"

def download_and_parse():
    print("📥 Downloading CVE feed from NVD...")
    headers = {'User-Agent': 'ScannerV2/1.0'}
    response = requests.get(NVD_URL, headers=headers)
    if response.status_code != 200:
        print(f"❌ Failed to download CVE feed (HTTP {response.status_code})")
        return

    with open(JSON_FILE, "wb") as f:
        f.write(response.content)

    print("🔍 Extracting and parsing JSON feed...")
    with gzip.open(JSON_FILE, "rt", encoding="utf-8") as f:
        data = json.load(f)

    print("📦 Inserting CVEs into database...")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cves (
        cve_id TEXT PRIMARY KEY,
        description TEXT,
        cvss_score REAL,
        severity TEXT,
        vendor TEXT,
        product TEXT,
        version TEXT
    )
    """)

    new_entries = 0
    skipped = 0

    for item in data.get("CVE_Items", []):
        try:
            cve_id = item["cve"]["CVE_data_meta"]["ID"]
            description_data = item["cve"]["description"]["description_data"]
            description = next((d["value"] for d in description_data if d["lang"] == "en"), "No English description")
            score = 0.0
            vendor, product, version = "unknown", "unknown", "unknown"

            impact = item.get("impact", {})
            if "baseMetricV3" in impact:
                score = impact["baseMetricV3"]["cvssV3"]["baseScore"]
            elif "baseMetricV2" in impact:
                score = impact["baseMetricV2"]["cvssV2"]["baseScore"]

            # FIXED: Accept any CPE entry, not just those marked "vulnerable"
            for node in item.get("configurations", {}).get("nodes", []):
                for match in node.get("cpe_match", []):
                    if "cpe23Uri" in match:
                        vendor, product, version = extract_vendor_product_version(match.get("cpe23Uri", ""))
                        break
                if vendor != "unknown":
                    break

            severity = classify_severity(score)

            cursor.execute("""
                INSERT OR IGNORE INTO cves (
                    cve_id, description, cvss_score, severity, vendor, product, version
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (cve_id, description, score, severity, vendor, product, version))

            new_entries += 1

        except Exception as e:
            skipped += 1
            print(f"⚠️ Error processing CVE {item.get('cve', {}).get('CVE_data_meta', {}).get('ID', 'unknown')}: {e}")

    conn.commit()
    conn.close()
    os.remove(JSON_FILE)

    print(f"✅ Finished. {new_entries} new CVEs added to the database.")
    if skipped > 0:
        print(f"⚠️ Skipped {skipped} entries due to errors.")

if __name__ == "__main__":
    download_and_parse()
