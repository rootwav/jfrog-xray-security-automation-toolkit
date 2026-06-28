import io
import time
import zipfile
import csv
import os
import sys
import re
import datetime
import requests

# --- CONFIGURATION ---
JFROG_URL = "https://YourOrg.jfrog.io"  

# Your Active JFrog Identity Token
API_TOKEN = "YourToken"

headers = {
    "Authorization": f"Bearer {API_TOKEN}"
}

# Aligned with the 4 repositories checked in your JFrog UI
TARGET_REPOSITORIES = [
    "common-maven-remote-cache",
    "common-npm-remote-cache",
    "common-nuget-remote-cache",
    "common-pypi-remote-cache"
]

# =====================================================================
# SYSTEM INTERFACE DISPLAY
# =====================================================================

def clear_terminal_screen():
    """Wipes the command terminal screen cleanly regardless of host platform ecosystem."""
    os.system('cls' if os.name == 'nt' else 'clear')

def render_static_banner():
    """Renders the custom framed retro banner, dynamically pulling environment variables."""
    display_url = JFROG_URL.rstrip("/")
    repo_count = len(TARGET_REPOSITORIES)
    
    node_str = f"||  Node   : {display_url}"
    scope_str = f"||  Scope  : {repo_count} Target Repositories"
    engine_str = "||  Engine : Active SCA Scanning Pipeline"
    
    line_width = 45 
    
    node_line = node_str + " " * (line_width - len(node_str)) + "||"
    scope_line = scope_str + " " * (line_width - len(scope_str)) + "||"
    engine_line = engine_str + " " * (line_width - len(engine_str)) + "||"
    empty_line = "||" + " " * (line_width - 2) + "||"
    
    banner_text = f"""//───=[ AppSec Attack Surface Identifier ]=───\\\\
{empty_line}
{node_line}
{scope_line}
{engine_line}
\\\\───────────────────────────────────────────//"""
    
    print("[.] Initializing AppSec Attack Surface Core...")
    time.sleep(0.2)
    
    for line in banner_text.split('\n'):
        print(line)
        time.sleep(0.02)
        
    print(f"\n+[ AppSec-v1.0-release | {repo_count} repositories cached | token active ]")
    print(f"└─> \"Automating vulnerability tracking turns chaos into clarity.\"\n")
    time.sleep(0.1)

# =====================================================================
# SYSTEM ENGINE UTILITIES
# =====================================================================

def get_unique_filename(base_name):
    """Checks the local workspace and increments the filename to prevent overwrites."""
    if not os.path.exists(base_name):
        return base_name
    
    name, ext = os.path.splitext(base_name)
    counter = 1
    while True:
        new_name = f"{name}_{counter}{ext}"
        if not os.path.exists(new_name):
            return new_name
        counter += 1

# =====================================================================
# FEATURE 2: LOCAL EXISTENCE SCANNERS (FULL STRATEGIC SURFACE AUDIT)
# =====================================================================

def search_packages_by_properties(package_list):
    """Audits storage files with a highly simplified security status matrix and precise column orders."""
    base_url = JFROG_URL.rstrip("/")
    search_url = f"{base_url}/artifactory/api/search/artifact"
    
    output_filename = get_unique_filename("Package_existence_report.csv")
    
    clean_display_list = [str(p).strip("[]'\" ").strip() for p in package_list if str(p).strip("[]'\" ").strip()]
    print(f"\n[*] Checking package existence for: {', '.join(clean_display_list)}...")
    raw_files = []
    
    has_execution_failure = False
    
    for package in package_list:
        clean_package = str(package).strip("[]'\" ").strip()
        if not clean_package:
            continue
            
        query_params = {"name": f"*{clean_package}*", "repos": ",".join(TARGET_REPOSITORIES)}
        
        try:
            response = requests.get(search_url, headers=headers, params=query_params, timeout=10)
            
            if response.status_code in [401, 403]:
                if not has_execution_failure:
                    print("[!] Error: Authentication failure please check URL and API key")
                    has_execution_failure = True
                break
            elif response.status_code != 200:
                print(f"[-] Search API query failed for '{clean_package}' (Status {response.status_code})")
                continue
                
            results = response.json().get("results", [])
        except Exception:
            if not has_execution_failure:
                print("[!] Error: Authentication failure please check URL and API key")
                has_execution_failure = True
            break
            
        for item in results:
            uri = item.get("uri", "")
            readable_path = uri.replace(f"{base_url}/artifactory/api/storage/", "")
            path_parts = [p for p in readable_path.split("/") if p and p != "-"]
            if not path_parts or not path_parts[-1].endswith(".tgz"):
                continue
                
            display_pkg_name = path_parts[1] if len(path_parts) > 1 else "N/A"
            base_file = path_parts[-1][:-4]
            
            if base_file.startswith(display_pkg_name + "-"):
                version_token = base_file[len(display_pkg_name) + 1:]
            else:
                match = re.search(r'-(\d+\.\d+\.\d+.*)', base_file)
                version_token = match.group(1) if match else "N/A"
                
            full_server_path = "/".join(path_parts)
            if clean_package.lower() not in full_server_path.lower():
                continue
                
            download_count = 0
            last_used_str = "Never Used"
            last_used_epoch = 0
            
            stats_res = requests.get(f"{uri}?stats", headers=headers)
            if stats_res.status_code == 200:
                stats_data = stats_res.json()
                download_count = stats_data.get("downloadCount", 0)
                raw_last_downloaded = stats_data.get("lastDownloaded", 0)
                if download_count > 0 and raw_last_downloaded != 0:
                    last_used_str = datetime.datetime.fromtimestamp(int(str(raw_last_downloaded)[:10])).strftime('%d-%m-%Y')

            raw_files.append({
                "package_name": display_pkg_name,
                "server_path": full_server_path,
                "version": version_token,
                "download_count": download_count,
                "last_used": last_used_str,
                "last_used_epoch": last_used_epoch
            })

    if not raw_files:
        if not has_execution_failure:
            print(f"\n[-] No package matches found across remote cache frameworks for: '{', '.join(clean_display_list)}'")
        return

    package_groups = {}
    for f in raw_files:
        package_groups.setdefault(f["package_name"], []).append(f)
        
    final_rows = []
    
    for pkg_name, files in package_groups.items():
        sorted_files = sorted(files, key=lambda x: [int(c) if c.isdigit() else c for c in re.split(r'(\d+)', x["version"])])
        latest_version = sorted_files[-1]["version"]
        
        active_version = max(files, key=lambda x: (x["download_count"], x["last_used_epoch"]))["version"]
        
        for file_item in reversed(sorted_files):
            if file_item["version"] == latest_version:
                security_context = "UP TO DATE"
            else:
                security_context = "OUTDATED"
                
            final_rows.append([
                file_item["package_name"],
                file_item["server_path"],
                latest_version,
                active_version,
                security_context,
                file_item["download_count"],
                file_item["last_used"],
                "ACTIVE" if file_item["download_count"] > 0 else "INACTIVE"
            ])

    try:
        with open(output_filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Package Name", "Full Server Path", 
                "Latest Version", "Active Version(in your Env)", "Security Context",
                "Local Download Count", "Last Used in Env", "Status"
            ])
            writer.writerows(final_rows)
        print(f"\n[+] Report generated successfully: {os.path.basename(output_filename)}")
    except Exception as e:
        print(f"[-] Failed writing output database report to disk: {e}")

# =====================================================================
# FEATURE 1: MULTI-CVE SORTED ASYNC REPORT SUITE
# =====================================================================

def generate_multi_cve_report(cve_list):
    base_url = JFROG_URL.rstrip("/")
    trigger_url = f"{base_url}/xray/api/v1/reports/vulnerabilities"
    timestamp = int(time.time())
    report_name = f"Multi_CVE_Report_{timestamp}"
    report_headers = {"Authorization": f"Bearer {API_TOKEN}", "Content-Type": "application/json"}
    payload = {
        "name": report_name,
        "resources": {"repositories": [{"name": repo} for repo in TARGET_REPOSITORIES]},
        "filters": {"cves": cve_list}
    }
    print(f"\n[*] Triggering standard Vulnerability Report for CVEs: {', '.join(cve_list)}...")
    
    try:
        response = requests.post(trigger_url, json=payload, headers=report_headers, timeout=10)
        
        if response.status_code in [401, 403]:
            print("[!] Error: Authentication failure please check URL and API key")
            return None, report_name
        elif response.status_code not in [200, 201]:
            print(f"[-] Failed to trigger report (Status {response.status_code}): {response.text}")
            return None, report_name
            
        return response.json().get("report_id"), report_name
    except Exception:
        print("[!] Error: Authentication failure please check URL and API key")
        return None, report_name

def filter_and_save_sorted_csv(zip_content, cve_list):
    try:
        with zipfile.ZipFile(io.BytesIO(zip_content)) as z:
            for file_info in z.infolist():
                if file_info.filename.endswith('.csv'):
                    raw_data = z.read(file_info.filename).decode('utf-8')
                    csv_reader = csv.reader(io.StringIO(raw_data))
                    header = next(csv_reader)
                    all_extracted_rows = list(csv_reader)
                    sorted_filtered_rows = []
                    
                    for target_cve in cve_list:
                        target_cve_clean = target_cve.strip().lower()
                        match_count = 0
                        for row in all_extracted_rows:
                            if any(target_cve_clean in str(col).lower() for col in row):
                                sorted_filtered_rows.append(row)
                                match_count += 1
                        print(f"   Collected {match_count} records for {target_cve.strip()}")
                    
                    if not sorted_filtered_rows:
                        formatted_cves = ", ".join([c.strip() for c in cve_list])
                        print(f"\n[+] Great! No records found across your environment for: {formatted_cves}")
                        return

                    output_filename = get_unique_filename("CVE_Report.csv")
                    with open(output_filename, "w", newline="", encoding="utf-8") as f:
                        writer = csv.writer(f)
                        writer.writerow(header)
                        writer.writerows(sorted_filtered_rows)
                    print(f"\n[+] Report generated successfully: {os.path.basename(output_filename)}")
                    return
    except Exception as e:
        print(f"[-] Error sorting report data: {e}")

def download_report_csv(report_id, report_name, cve_list):
    base_url = JFROG_URL.rstrip("/")
    status_url = f"{base_url}/xray/api/v1/reports/{report_id}"
    print("[*] Waiting for report generation to complete...")
    report_headers = {"Authorization": f"Bearer {API_TOKEN}", "Content-Type": "application/json"}
    
    CYAN, GREEN, RESET, WHITE = "\033[36m", "\033[32m", "\033[0m", "\033[97m"
    while True:
        try:
            status_response = requests.get(status_url, headers=report_headers, timeout=10)
            if status_response.status_code in [401, 403]:
                print("\n[!] Error: Authentication failure please check URL and API key")
                return
            elif status_response.status_code != 200:
                break
                
            status_data = status_response.json()
        except Exception:
            print("\n[!] Error: Authentication failure please check URL and API key")
            return
            
        status = status_data.get("status", "").lower()
        progress_val = status_data.get("progress", 0)
        
        bar_length = 30
        filled_length = int(round(bar_length * progress_val / 100))
        bar = f"{GREEN}{'━' * filled_length}{RESET}{'─' * (bar_length - filled_length)}"
        print(f"\r    Current Status: {CYAN}{status.upper():<9}{RESET} ▕{bar}▏ {WHITE}{progress_val}% completed{RESET}", end="", flush=True)
        
        if status == "completed":
            print()
            break
        elif status in ["failed", "error"]:
            print(f"\n[-] Report generation failed on the server backend.")
            return
        time.sleep(10)
        
    time.sleep(5)
    export_url = f"{base_url}/xray/api/v1/reports/export/{report_id}"
    query_params = {"file_name": report_name, "format": "csv"}
    export_headers = {"Authorization": f"Bearer {API_TOKEN}", "Accept": "application/zip"}
    response = requests.get(export_url, headers=export_headers, params=query_params)
    if response.status_code == 200:
        filter_and_save_sorted_csv(response.content, cve_list)

# =====================================================================
# FEATURE 3: LIST AND PERMANENTLY DELETE ENGINE (PERSISTENT LOOPING)
# =====================================================================

def list_and_delete_vulnerability_reports():
    """Lists compliance reports and enables persistent range deletion re-prompt cycles."""
    base_url = JFROG_URL.rstrip("/")
    url = f"{base_url}/xray/api/v1/reports?direction=desc&page_num=1&num_of_rows=100&order_by=start_time"
    report_headers = {"Authorization": f"Bearer {API_TOKEN}", "Content-Type": "application/json"}
    
    print("[*] Fetching current live report listing from server...")
    
    try:
        response = requests.post(url, headers=report_headers, timeout=10)
        if response.status_code in [401, 403]:
            print("[!] Error: Authentication failure please check URL and API key")
            return
        elif response.status_code != 200:
            print(f"[-] Failed to fetch report listing (Status {response.status_code})")
            return
            
        json_data = response.json()
    except Exception:
        print("[!] Error: Authentication failure please check URL and API key")
        return

    reports_list = json_data.get("reports", []) if isinstance(json_data, dict) else json_data
    if not reports_list:
        print("\n[!] No active reports found stored on the server back-end.")
        return

    print("\n======================================================================")
    print("REPORT ID    | REPORT NAME                         | STATUS         ")
    print("======================================================================")
    for report in reports_list:
        if isinstance(report, str):
            continue
        print(f"{str(report.get('id', 'N/A')):<12} | {str(report.get('name', 'N/A')):<35} | {str(report.get('status', 'N/A')).upper():<15}")
    print("======================================================================\n")
    print(f"Total reports:{len(reports_list)}")

    is_first_attempt = True
    while True:
        if is_first_attempt:
            target_input = input("Enter Report ID to delete: ").strip()
        else:
            target_input = input("Re-enter Report ID to delete: ").strip()
            
        if not target_input or target_input.lower() == 'cancel':
            print("[*] Operation canceled. Returning to main engine menu.")
            return

        chunks = [c.strip() for c in target_input.split(",") if c.strip()]
        target_ids = set()
        has_error = False
        
        for chunk in chunks:
            if "-" in chunk:
                parts = chunk.split("-")
                if len(parts) == 2 and parts[0].strip().isdigit() and parts[1].strip().isdigit():
                    start, end = int(parts[0].strip()), int(parts[1].strip())
                    if start > end:
                        start, end = end, start
                    for num in range(start, end + 1):
                        target_ids.add(str(num))
                else:
                    print(f"\n[!] Error: Invalid range format detected ('{chunk}'). Please provide valid input.")
                    has_error = True
                    break
            else:
                if chunk.isdigit():
                    target_ids.add(chunk)
                else:
                    print(f"\n[!] Error: Invalid report ID detected ('{chunk}'). Please provide valid input.")
                    has_error = True
                    break

        if has_error:
            is_first_attempt = False
            continue

        if not target_ids:
            print("\n[!] Error: No valid report IDs provided. Please provide valid input.")
            is_first_attempt = False
            continue

        break

    final_execution_list = sorted(list(target_ids), key=int)
    print(f"[*] Initializing connection sequence to purge {len(final_execution_list)} items...")
    
    for item in final_execution_list:
        sys.stdout.write(f"\r Deleting Report ID: ➔ {item} ")
        sys.stdout.flush()
        delete_url = f"{base_url}/xray/api/v1/reports/{item}"
        # FIXED: Named the keyword argument explicitly so requests handles parameters accurately
        requests.delete(delete_url, headers=report_headers)
        time.sleep(0.05)
        
    print(f"\n[+] successfully Deleted ID: {item}")

# =====================================================================
# SYSTEM OPERATIONAL ROUTING INTERFACE
# =====================================================================

if __name__ == "__main__":
    clear_terminal_screen()
    render_static_banner()
    
    print("============================================================")
    print("         AppSec Attack Surface Identifier                   ")
    print("============================================================")
    print("1. Search Vulnerabilities by CVE ID(s)                      ")
    print("2. Check Package Existence in Repositories                  ") 
    print("3. Delete Existing Reports Stored on Server                 ")
    print("------------------------------------------------------------")
    
    choice = input("Select an option (1-3): ").strip()
    if choice == "1":
        user_input = input("Enter CVE IDs separated by commas: ").strip()
        if user_input:
            cves = [c.strip() for c in user_input.split(",") if c.strip()]
            r_id, r_name = generate_multi_cve_report(cves)
            if r_id and r_name:
                download_report_csv(r_id, r_name, cves)
    elif choice == "2":
        user_input = input("Enter Package/Component Names (separated by commas): ").strip()
        if user_input:
            packages = [p.strip() for p in user_input.split(",") if p.strip()]
            search_packages_by_properties(packages)
    elif choice == "3":
        list_and_delete_vulnerability_reports()