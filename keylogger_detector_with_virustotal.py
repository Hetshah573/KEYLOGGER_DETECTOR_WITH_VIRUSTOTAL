import psutil
import pefile
import yara
import os
import sys
import time
import argparse
from datetime import datetime
import hashlib
from dotenv import load_dotenv
import requests

def parse_args():
    parser = argparse.ArgumentParser(
        description="Keylogger Detection Tool with interval scanning and custom YARA rules"
    )
    parser.add_argument(
        "-r", "--rules",
        default="keylogger_rules.yar",
        help="Path to YARA rules file (default: keylogger_rules.yar)"
    )
    parser.add_argument(
        "-i", "--interval",
        type=int,
        default=60,
        help="Scan interval in seconds (minimum 60 seconds, default: 60)"
    )
    return parser.parse_args()

def compile_yara_rules(rules_path):
    if not os.path.isfile(rules_path):
        print(f"[Error] YARA rules file not found: {rules_path}")
        sys.exit(1)
    try:
        rules = yara.compile(filepath=rules_path)
        print(f"[Info] Loaded YARA rules from: {rules_path}")
        return rules
    except yara.Error as e:
        print(f"[Error] Failed to compile YARA rules: {e}")
        sys.exit(1)

def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def vt_check_file(api_key, file_path):
    if not os.path.isfile(file_path):
        return None, None, None

    sha256_hash = sha256_of_file(file_path)
    # print(sha256_hash)
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = { "x-apikey": api_key }

    try:
        response = requests.get(url, headers=headers, timeout=15)
    except requests.RequestException as e:
        return sha256_hash, None, None

    if response.status_code == 200:
        data = response.json().get("data", {})
        stats = data.get("attributes", {}).get("last_analysis_stats", {})
        positives = stats.get("malicious", 0)
        total_engines = sum(stats.values())
        return sha256_hash, positives, total_engines
    elif response.status_code == 404:
        return sha256_hash, 0, 0
    else:
        return sha256_hash, None, None
    
def scan_processes(api_key,yara_rules):
    findings = []
    for proc in psutil.process_iter(attrs=["pid", "name", "exe", "cmdline"]):
        try:
            pid      = proc.info["pid"]
            name     = (proc.info["name"] or "").lower()
            exe_path = proc.info["exe"] or ""

            if pid == 0 or name in ("system", "idle"):
                continue

            # Heuristic #1: name contains "keylog"
            if "keylog" in name and exe_path:
                sha256_hash, positives, total_engines = vt_check_file(api_key, exe_path)
                if positives is not None and positives > 0:
                    findings.append((pid, name, exe_path, sha256_hash, positives, total_engines,
                                     "Name-based heuristic + VT"))
                else:
                    findings.append((pid, name, exe_path, sha256_hash, positives, total_engines,
                                     "Name-based heuristic"))
                continue

            # Heuristic #2: import scan
            if exe_path.lower().endswith(".exe") and os.path.isfile(exe_path):
                try:
                    pe = pefile.PE(exe_path, fast_load=True)
                    pe.parse_data_directories(
                        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
                    )
                    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                        for entry in pe.DIRECTORY_ENTRY_IMPORT:
                            for imp in entry.imports:
                                if imp.name:
                                    imp_name = imp.name.decode(errors="ignore")
                                    if imp_name in ("SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState"):
                                        sha256_hash, positives, total_engines = vt_check_file(api_key, exe_path)
                                        if positives is not None and positives > 0:
                                            findings.append((pid, name, exe_path, sha256_hash, positives, total_engines,
                                                             f"Import heuristic: {imp_name} + VT"))
                                        else:
                                            findings.append((pid, name, exe_path, sha256_hash, positives, total_engines,
                                                             f"Import heuristic: {imp_name}"))
                                        raise StopIteration
                except (pefile.PEFormatError, StopIteration):
                    pass

            # YARA scan
            if exe_path and os.path.isfile(exe_path):
                matches = yara_rules.match(exe_path)
                if matches:
                    sha256_hash, positives, total_engines = vt_check_file(api_key, exe_path)
                    rule_names = [r.rule for r in matches]
                    if positives is not None and positives > 0:
                        findings.append((pid, name, exe_path, sha256_hash, positives, total_engines,
                                         f"YARA match: {rule_names} + VT"))
                    else:
                        findings.append((pid, name, exe_path, sha256_hash, positives, total_engines,
                                         f"YARA match: {rule_names}"))
                    continue

        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue

    return findings

def main():
    load_dotenv()
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        print("[Error] VT_API_KEY not found in .env")
    else:
        print("Loaded VT_API_KEY successfully")
    args = parse_args()
    interval = args.interval
    if interval < 60:
        print(f"[Warning] Provided interval {interval}s is less than minimum (60s). Using 60s instead.")
        interval = 60

    yara_rules = compile_yara_rules(args.rules)

    print(f"[Info] Starting scanning every {interval} seconds. Press Ctrl+C to exit.\n")
    try:
        while True:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"=== Scan started at {timestamp} ===")
            results = scan_processes(api_key,yara_rules)
            if results:
                print("=== Possible Keylogger Artifacts Detected (with VT info) ===")
                for pid, proc_name, exe_path, sha256_hash, positives, total_engines, reason in results:
                    if positives is None:
                        vt_status = "VT check failed or rate-limited"
                    elif positives > 0:
                        vt_status = f"Malicious ({positives}/{total_engines})"
                    else:
                        vt_status = f"No detections (0/{total_engines})"
                    # only prints the details if finds malicious count by virustotal to be more than 0
                    if(positives>0):
                        print(
                            f"PID={pid:<6}  Name={proc_name:<20}  File={os.path.basename(exe_path):<20}  "
                            f"Hash={sha256_hash}  VT={vt_status}  Reason={reason}"
                        )    
            else:
                 print("No obvious keylogger patterns found.")
            print(f"=== Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[Info] Scan interrupted by user. Exiting.")
        sys.exit(0)

if __name__ == "__main__":
    main()
