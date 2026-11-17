import os
import json
import sqlite3
import bcrypt
import sys
import subprocess
import requests
import re
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
from update_cves import download_and_parse
from subprocess import Popen
from collections import defaultdict
from service_attack_mapping import SERVICE_ATTACK_MAP

app = Flask(__name__)
app.secret_key = "your_secret_key"

DB_PATH = os.path.join("data", "vulnerabilities.db")
USER_DB_PATH = os.path.join("users.db")
os.makedirs("data", exist_ok=True)
os.makedirs("scans", exist_ok=True)

@app.route("/")
def home():
    return redirect(url_for("dashboard"))

@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cves")
        total_cves = cursor.fetchone()[0]
        severity_counts = {
            "critical": cursor.execute("SELECT COUNT(*) FROM cves WHERE cvss_score >= 9.0").fetchone()[0],
            "high": cursor.execute("SELECT COUNT(*) FROM cves WHERE cvss_score >= 7.0 AND cvss_score < 9.0").fetchone()[0],
            "medium": cursor.execute("SELECT COUNT(*) FROM cves WHERE cvss_score >= 4.0 AND cvss_score < 7.0").fetchone()[0],
            "low": cursor.execute("SELECT COUNT(*) FROM cves WHERE cvss_score > 0.0 AND cvss_score < 4.0").fetchone()[0],
            "info": cursor.execute("SELECT COUNT(*) FROM cves WHERE cvss_score = 0.0 OR cvss_score IS NULL").fetchone()[0],
        }
        conn.close()
        report_count = len([f for f in os.listdir("scans") if f.endswith(".txt")])
        return render_template("dashboard.html", total_cves=total_cves, severity_counts=severity_counts, report_count=report_count)
    except Exception as e:
        print(f"[!] Error loading dashboard: {e}")
        return render_template("dashboard.html", total_cves=0, severity_counts={}, report_count=0)

MITRE_ATTACK_PATH = "/root/cti/enterprise-attack/enterprise-attack.json"

with open(MITRE_ATTACK_PATH, "r", encoding="utf-8") as f:
    mitre_json = json.load(f)

# Build a lookup dictionary: technique_id -> {details}
MITRE_TECH_LOOKUP = {}
for obj in mitre_json["objects"]:
    if obj["type"] == "attack-pattern":
        for ref in obj.get("external_references", []):
            if ref.get("external_id"):
                MITRE_TECH_LOOKUP[ref["external_id"]] = {
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "url": ref.get("url", ""),
                }

# --- Start HackTricks offline HTTP server if not already running ---
def start_hacktricks_server():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(('127.0.0.1', 8080))
        s.close()
        print("[INFO] HackTricks server already running on 8080.")
    except ConnectionRefusedError:
        print("[INFO] Starting HackTricks server on 8080...")
        subprocess.Popen(
            [sys.executable, "-m", "http.server", "8080", "--directory", "hacktricks-offline/book.hacktricks.wiki"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
start_hacktricks_server()

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = sqlite3.connect(USER_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username=?", (username,))
        result = cursor.fetchone()
        conn.close()
        if result:
            stored_hash = result[0].encode() if isinstance(result[0], str) else result[0]
            if bcrypt.checkpw(password.encode(), stored_hash):
                session["logged_in"] = True
                session["username"] = username
                return redirect(url_for("dashboard"))
        error = "Invalid credentials"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("login"))

@app.route("/scanner", methods=["GET", "POST"])
def scanner():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    if request.method == "POST":
        ip = request.form["ip_address"]
        ports = request.form["ports"]
        filename = request.form["output_file"]

        # Automatically add .txt if not present
        if not filename.lower().endswith(".txt"):
            filename += ".txt"

        output_path = os.path.join("scans", filename)

        # Validate inputs
        if not ip or not ports:
            flash("❌ Invalid input provided.", "danger")
            return redirect(url_for("scanner"))

        port_regex = r"^(\d+(-\d+)?)(,\d+(-\d+)?)*$"
        if not re.match(port_regex, ports):
            flash("❌ Port format is invalid. Use formats like 80,443 or 1-1000", "danger")
            return redirect(url_for("scanner"))

        scanner_path = os.path.join(os.getcwd(), "nmap_scanner.py")

        try:
            result = subprocess.run(
                [sys.executable, scanner_path, ip, ports, output_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            flash(f"✅ Scan for {ip} completed. Check the reports.", "success")
        except subprocess.CalledProcessError as e:
            flash(f"❌ Scan failed: {e.stderr}", "danger")
        except Exception as e:
            flash(f"❌ Unexpected error: {str(e)}", "danger")

        return redirect(url_for("reports"))

    return render_template("scanner.html")

@app.route("/reports")
def reports():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    files = [f for f in os.listdir("scans") if f.endswith(".txt")]
    return render_template("reports.html", reports=files)

@app.route("/reports/<path:filename>")
def report_detail(filename):
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    filepath = os.path.join("scans", filename)
    if not os.path.exists(filepath):
        return "Report not found", 404

    # --- Read the scan report file ---
    with open(filepath, "r") as f:
        content = f.readlines()

    # --- Prepare DB connection ---
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # --- Data structures ---
    details = {}          # Per-IP: list of services and CVEs
    stats = {}            # Stats per service/port (not used in template now)
    global_cves = {}      # CVE summary (one entry per unique CVE)
    severity_count = defaultdict(int)
    device_table = {}
    current_ip = "" 
    detected_services = set()

    # --- Parse Nmap output and lookup CVEs ---
    for line in content:
        line = line.strip()
        # New host
        if line.startswith("Nmap scan report for"):
            current_ip = line.replace("Nmap scan report for", "").strip()
            details[current_ip] = []
            continue
        # Open TCP service line
        if "/tcp" in line and "open" in line:
            parts = line.split()
            port = parts[0].split("/")[0]
            service = parts[2]
            detected_services.add(service.lower())
            version_raw = " ".join(parts[3:]) if len(parts) > 3 else "unknown"
            version_clean = re.sub(r"[^\d.]", "", version_raw.split()[0]) if version_raw != "unknown" else ""

            # CVE lookup by service + version (fuzzy)
            if version_clean:
                cursor.execute("""
                    SELECT cve_id, description, severity FROM cves
                    WHERE LOWER(product) LIKE ? AND version LIKE ?
                    ORDER BY severity DESC LIMIT 5
                """, (f"%{service.lower()}%", f"{version_clean}%"))
            else:
                cursor.execute("""
                    SELECT cve_id, description, severity FROM cves
                    WHERE LOWER(product) LIKE ?
                    ORDER BY severity DESC LIMIT 5
                """, (f"%{service.lower()}%",))

            rows = cursor.fetchall()
            cves = [r[0] for r in rows]

            for r in rows:
                cve_id = r[0]
                severity = r[2].lower()
                severity_count[severity] += 1
                # Build global CVE table
                if cve_id not in global_cves:
                    global_cves[cve_id] = {
                        "id": cve_id,
                        "description": r[1],
                        "severity": r[2],
                        "exploitable": any(x in r[1].lower() for x in ["rce", "exec", "exploit", "code execution"]),
                        "remediation": "Apply vendor patch or implement network filtering as mitigation.",
                        "exploitdb": f"https://www.exploit-db.com/search?q={cve_id}",
                        "impacted": [f"{current_ip}:{port}"]
                    }
                else:
                    impacted_key = f"{current_ip}:{port}"
                    if impacted_key not in global_cves[cve_id]["impacted"]:
                        global_cves[cve_id]["impacted"].append(impacted_key)

            # --- MITRE ATT&CK techniques for this service ---
            mitre_techniques = []
            if service.lower() in SERVICE_ATTACK_MAP:
                for tech_id in SERVICE_ATTACK_MAP[service.lower()]:
                    tech = MITRE_TECH_LOOKUP.get(tech_id)
                    if tech:
                        mitre_techniques.append({
                            "id": tech_id,
                            "name": tech["name"],
                            "description": tech["description"],
                            "url": tech["url"]
                        })

            details[current_ip].append({
                "port": port,
                "service": service,
                "version": version_raw,
                "cves": cves,
                "mitre_techniques": mitre_techniques
            })

    # --- Device table (IP summary, risk) ---
    for ip, entries in details.items():
        services = [{"port": int(e["port"]), "service": e["service"], "banner": e["version"]} for e in entries]
        device_table[ip] = {
            "services": services,
            "device_type": "Unknown",
            "risk_score": len(entries) * 10,
            "risk_level": "High" if len(entries) >= 3 else "Medium" if len(entries) == 2 else "Low"
        }

    # --- Exploitable summary table: count per severity ---
    exploitable_count_dict = {sev: 0 for sev in ['critical', 'high', 'medium', 'low', 'informational']}
    for cve in global_cves.values():
        sev = cve["severity"].lower()
        if cve["exploitable"] and sev in exploitable_count_dict:
            exploitable_count_dict[sev] += 1

    # --- PRINT detected services for mapping expansion ---
    print("\n[INFO] Services detected in this scan:", sorted(detected_services), "\n")

    conn.close()
    return render_template(
        "report_detail.html",
        filename=filename,
        details=details,
        stats=stats,
        cve_data=global_cves,
        severity_count=dict(severity_count),
        devices=device_table,
        exploitable_count_dict=exploitable_count_dict,
    )

@app.route("/download_cves")
def download_cves():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    try:
        download_and_parse()
        flash("✅ CVE database updated successfully.", "success")
    except Exception as e:
        flash(f"❌ CVE update failed: {e}", "danger")
    return redirect(url_for("dashboard"))

@app.route("/manage_users", methods=["GET", "POST"])
def manage_users():
    if not session.get("logged_in"):
        flash("❌ Please login first.", "danger")
        return redirect(url_for("login"))

    conn = sqlite3.connect(USER_DB_PATH)
    cursor = conn.cursor()

    # Check if users table is empty (first-time setup)
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]

    if user_count > 0 and session.get("username") != "admin":
        flash("❌ Access denied. Admins only.", "danger")
        conn.close()
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        if "add_user" in request.form:
            username = request.form["new_username"]
            password = request.form["new_password"]
            role = request.form["new_role"]
            hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            try:
                cursor.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    (username, hashed_pw, role)
                )
                flash(f"✅ User '{username}' added as '{role}'.", "success")
            except sqlite3.IntegrityError:
                flash(f"❌ Username '{username}' already exists.", "danger")

        elif "update_role" in request.form:
            user_id = request.form["user_id"]
            role = request.form["role"]
            cursor.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
            flash("🔄 Role updated.", "info")

        elif "delete_user" in request.form:
            user_id = request.form["user_id"]
            cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
            flash("❌ User deleted.", "warning")

        conn.commit()

    cursor.execute("SELECT id, username, role FROM users")
    users = cursor.fetchall()
    conn.close()

    return render_template("manage_users.html", users=users)

@app.route("/delete_report/<path:filename>", methods=["POST"])
def delete_report(filename):
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    # Only allow deleting files ending with .txt in scans dir for safety
    file_path = os.path.join("scans", filename)
    if os.path.exists(file_path) and file_path.endswith(".txt"):
        os.remove(file_path)
        flash(f"🗑 Report '{filename}' deleted.", "success")
    else:
        flash(f"❌ Report not found or invalid filename.", "danger")
    return redirect(url_for("reports"))

@app.route('/ai_exploit/<path:filename>')
def ai_exploit(filename):
    filepath = os.path.join("scans", filename)
    if not os.path.exists(filepath):
        return Response("Report not found.", status=404)

    try:
        with open(filepath, "r") as f:
            lines = f.readlines()
    except Exception as e:
        return Response("Could not read report: " + str(e), status=500)

    # --- Parse Nmap output for services, CVEs, MITREs (simple) ---
    summary = []
    current_ip = ""
    for line in lines:
        line = line.strip()
        if line.startswith("Nmap scan report for"):
            current_ip = line.replace("Nmap scan report for", "").strip()
            continue
        if "/tcp" in line and "open" in line:
            parts = line.split()
            port = parts[0].split("/")[0]
            service = parts[2]
            version = " ".join(parts[3:]) if len(parts) > 3 else "unknown"
            summary.append(f"IP: {current_ip}, Port: {port}, Service: {service}, Version: {version}")

    # Get CVEs/techniques for prompt context (for better LLM suggestion quality)
    cve_list = []
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT cve_id, description, severity FROM cves ORDER BY RANDOM() LIMIT 10")
        cve_list = cursor.fetchall()
        conn.close()
    except Exception:
        pass

    cve_text = "\n".join([f"{row[0]} ({row[2]}): {row[1][:120]}..." for row in cve_list])

    # 2. Build an LLM prompt for "Exploit Suggestion" (indentation fixed!)
    prompt = f"""
The following is a summary of a network vulnerability scan report.

Scan Summary (truncated):
{chr(10).join(summary)}

Relevant CVEs found:
{cve_text}

You are a top red teamer and exploitation expert.

**For each IP/service/port, provide:**
- A full exploitation path (realistic and technical).
- Actual command lines or tools (e.g., sqlmap, hydra, nmap, metasploit, responder, etc) to use for each step, including example commands (with options and placeholders where necessary).
- The relevant section or link from HackTricks (local mirror at http://0.0.0.0:8080/book.hacktricks.wiki/) or any other well-known resource.
- A post-exploitation action and the most likely attacker goal.
- Detection/mitigation tips.

**Format your answer as:**
- IP:PORT/SERVICE
  - Step 1: <detailed action, with command or tool, and why>
    - Example: sudo ./sqlmap.py -u "http://<target>/vuln.php?id=1" --batch --banner --forms --crawl=2 --tamper=space2comment --random-agent
    - Reference: http://0.0.0.0:8080/book.hacktricks.wiki/wikis/sql-injection.html
  - Step 2: <...>
  - Post-exploitation: <...>
  - Detection/mitigation tip: <...>

**Go deep**: suggest privilege escalation, pivoting, data extraction, or lateral movement techniques as appropriate. Always cross-reference HackTricks if possible. Only use local URLs.
"""

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": "llama3", "prompt": prompt, "stream": False},
            timeout=600
        )
        if response.status_code == 200:
            suggestion = response.json().get("response", "").replace('\n', '<br>')
            if not suggestion.strip():
                suggestion = "<span style='color:red;'>No suggestions returned from AI.</span>"
        else:
            suggestion = f"<span style='color:red;'>AI request failed. {response.status_code}: {response.text}</span>"
    except Exception as e:
        suggestion = f"<span style='color:red;'>AI request failed: {str(e)}</span>"

    html = f"""
    <div>
      <div style='color:#444;font-size:16px;line-height:1.6;'>{suggestion}</div>
      <div style='margin-top:18px;color:#888;font-size:13px;'>AI Exploiter powered by llama3 | Beta</div>
    </div>
    """
    return Response(html, mimetype="text/html")
