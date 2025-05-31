import psutil
import pefile
import yara
import os
import sys
import time
import argparse
from datetime import datetime

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

def scan_processes(yara_rules):
    findings = []
    for proc in psutil.process_iter(attrs=["pid", "name", "exe", "cmdline"]):
        try:
            pid      = proc.info["pid"]
            name     = (proc.info["name"] or "").lower()
            exe_path = proc.info["exe"] or ""

            # Skip trivial or system processes
            if pid == 0 or name in ("system", "idle"):
                continue

            # Heuristic #1: Process name contains "keylog"
            if "keylog" in name:
                findings.append((pid, name, "Name-based heuristic"))
                continue

            # Heuristic #2: Static import scan via pefile
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
                                        findings.append((pid, name, f"Import heuristic: {imp_name}"))
                                        raise StopIteration
                except (pefile.PEFormatError, StopIteration):
                    pass

            # YARA scan (signature-based)
            if exe_path and os.path.isfile(exe_path):
                matches = yara_rules.match(exe_path)
                if matches:
                    rule_names = [r.rule for r in matches]
                    findings.append((pid, name, f"YARA match: {rule_names}"))
                    continue

        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    return findings

def main():
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
            results = scan_processes(yara_rules)
            if results:
                print("=== Possible Keylogger Artifacts Detected ===")
                for pid, proc_name, reason in results:
                    print(f"  PID={pid:<6}  Name={proc_name:<20}  Reason={reason}")
            else:
                print("No obvious keylogger patterns found.")
            print(f"=== Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[Info] Scan interrupted by user. Exiting.")
        sys.exit(0)

if __name__ == "__main__":
    main()
