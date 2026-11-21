#!/usr/bin/env python3
"""
Kaspersky to Wazuh alert JSON to Wazuh indexer.

Usage:
  python kaspersky_to_wazuh.py --simulate 500 --out alerts.ndjson          
  python kaspersky_to_wazuh.py --input ksc_export.cef --out alerts.ndjson   
  python kaspersky_to_wazuh.py --simulate 500 --push --host https://localhost:9200 --user admin --password 'xxx'      
"""
import argparse, json, random, re, sys, uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone

# Simulation
EVENTS = [
    ("GNRL_EV_VIRUS_FOUND", "Malicious object detected", 8, "Malware", "Quarantined"),
    ("GNRL_EV_OBJECT_DELETED", "Malicious object deleted", 7, "Malware", "Deleted"),
    ("GNRL_EV_ATTACK_DETECTED", "Network attack detected", 9, "NetworkAttack", "Blocked"),
    ("GNRL_EV_WEB_THREAT", "Web threat blocked", 6, "WebAV", "Blocked"),
    ("GNRL_EV_PROTECTION_DISABLED", "Protection component disabled", 9, "Protection", "None"),
    ("GNRL_EV_UPDATE_FAILED", "Database update failed", 4, "Update", "None"),
    ("GNRL_EV_SCAN_COMPLETED", "Scan task completed", 2, "Task", "None"),
    ("GNRL_EV_DEVICE_BLOCKED", "Removable device blocked", 5, "DeviceControl", "Blocked"),
]
MALWARE = ["Trojan.Win32.Agent", "HEUR:Trojan-Ransom.Win32.Generic",
           "Trojan-Downloader.Script.Generic", "not-a-virus:RiskTool.Win32.Agent"]
HOSTS = [(f"PC-{d}-{i:02d}", f"10.10.{n}.{20+i}")
         for n, d in enumerate(["ACC", "HR", "IT", "OPS"], 1) for i in range(1, 4)]
USERS = ["CORP\\\\ayoub", "CORP\\\\samia", "CORP\\\\karim", "CORP\\\\nadia"]


def simulate(n):
    now = datetime.now(timezone.utc)
    lines = []
    for _ in range(n):
        sig, name, sev, cat, act = random.choices(EVENTS, weights=[5, 2, 1, 4, 1, 3, 4, 2])[0]
        host, ip = random.choice(HOSTS)
        ts = now - timedelta(seconds=random.randint(0, 7 * 86400))
        ext = f"rt={int(ts.timestamp()*1000)} dhost={host} dst={ip} suser={random.choice(USERS)} cat={cat} act={act}"
        if cat in ("Malware", "WebAV"):
            ext += (f" fname={uuid.uuid4().hex[:6]}.exe filePath=C:\\\\Users\\\\Public"
                    f" fileHash={uuid.uuid4().hex} msg={random.choice(MALWARE)} detected")
        else:
            ext += f" msg={name}"
        lines.append(f"CEF:0|Kaspersky|Security Center|14.2|{sig}|{name}|{sev}|{ext}")
    return lines


# Parsing
def split_header(line):
    """Split the first 7 unescaped pipes; remainder is the extension."""
    parts, buf, i = [], "", 0
    while i < len(line) and len(parts) < 7:
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            buf += line[i:i + 2]; i += 2; continue
        if c == "|":
            parts.append(buf); buf = ""
        else:
            buf += c
        i += 1
    return parts, line[i:]


KEY_RE = re.compile(r"(?:(?<=\s)|^)([A-Za-z][A-Za-z0-9_]*)=")


def parse_extension(ext):
    out, matches = {}, list(KEY_RE.finditer(ext))
    for idx, m in enumerate(matches):
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(ext)
        out[m.group(1)] = ext[m.end():end].strip()
    return out


def parse_cef(line):
    line = line.strip()
    if not line.startswith("CEF:"):
        # syslog prefix before CEF? strip it
        pos = line.find("CEF:")
        if pos < 0:
            return None
        line = line[pos:]
    hdr, ext = split_header(line)
    if len(hdr) < 7:
        return None
    return {
        "cef_version": hdr[0].replace("CEF:", ""), "vendor": hdr[1], "product": hdr[2],
        "product_version": hdr[3], "signature_id": hdr[4], "name": hdr[5],
        "severity": int(hdr[6]) if hdr[6].isdigit() else 0, "ext": parse_extension(ext),
    }


# Mapping to wazuh
# rule IDs in Wazuh's custom range 100000-120000 Level is 0-15
RULE_MAP = {
    "GNRL_EV_VIRUS_FOUND": ("100201", 12, ["kaspersky", "malware"]),
    "GNRL_EV_OBJECT_DELETED": ("100202", 9, ["kaspersky", "malware"]),
    "GNRL_EV_ATTACK_DETECTED": ("100203", 13, ["kaspersky", "network_attack"]),
    "GNRL_EV_WEB_THREAT": ("100204", 8, ["kaspersky", "web_threat"]),
    "GNRL_EV_PROTECTION_DISABLED": ("100205", 12, ["kaspersky", "policy_violation"]),
    "GNRL_EV_UPDATE_FAILED": ("100206", 5, ["kaspersky", "update"]),
    "GNRL_EV_SCAN_COMPLETED": ("100207", 3, ["kaspersky", "task"]),
    "GNRL_EV_DEVICE_BLOCKED": ("100208", 7, ["kaspersky", "device_control"]),
}
AGENT_IDS = {}
counter = defaultdict(int)


def agent_id(name):
    if name not in AGENT_IDS:
        AGENT_IDS[name] = f"{len(AGENT_IDS)+1:03d}"
    return AGENT_IDS[name]


def to_wazuh(raw_line, ev, manager="wazuh-manager"):
    ext = ev["ext"]
    ms = int(ext["rt"]) if ext.get("rt", "").isdigit() else int(datetime.now().timestamp() * 1000)
    dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    rid, default_lvl, groups = RULE_MAP.get(ev["signature_id"], ("100299", max(ev["severity"], 3), ["kaspersky"]))
    counter[rid] += 1
    host = ext.get("dhost", "unknown")
    data = {
        "kaspersky": {
            "signature_id": ev["signature_id"], "event_name": ev["name"],
            "severity": ev["severity"], "category": ext.get("cat"),
            "action": ext.get("act"), "message": ext.get("msg"),
            "product": ev["product"], "product_version": ev["product_version"],
        },
        "srcuser": ext.get("suser"),
    }
    if "fname" in ext:
        data["kaspersky"]["file_name"] = ext["fname"]
        data["kaspersky"]["file_path"] = ext.get("filePath")
    if "fileHash" in ext:
        data["kaspersky"]["file_hash"] = ext["fileHash"]
    data = {k: v for k, v in data.items() if v is not None}

    doc = {
        "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond//1000:03d}+0000",
        "rule": {
            "id": rid, "level": default_lvl, "description": f"Kaspersky: {ev['name']}",
            "groups": groups, "firedtimes": counter[rid], "mail": default_lvl >= 12,
        },
        "agent": {"id": agent_id(host), "name": host, **({"ip": ext["dst"]} if "dst" in ext else {})},
        "manager": {"name": manager},
        "id": f"{ms/1000:.3f}.{sum(counter.values())}",
        "full_log": raw_line.strip(),
        "decoder": {"name": "kaspersky-cef"},
        "data": data,
        "location": "kaspersky-ksc",
    }
    return doc, dt


# Output et push [ajoue env option]
def bulk_lines(docs):
    for doc, dt in docs:
        index = f"wazuh-alerts-4.x-{dt.strftime('%Y.%m.%d')}"
        yield json.dumps({"index": {"_index": index}})
        yield json.dumps({**doc, "@timestamp": dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")})


def push(docs, host, user, pwd, verify, chunk=500):
    import requests
    if not verify:
        import urllib3; urllib3.disable_warnings()
    lines = list(bulk_lines(docs))
    for i in range(0, len(lines), chunk * 2):
        body = "\n".join(lines[i:i + chunk * 2]) + "\n"
        r = requests.post(f"{host}/_bulk", data=body, auth=(user, pwd), verify=verify,
                          headers={"Content-Type": "application/x-ndjson"}, timeout=60)
        r.raise_for_status()
        res = r.json()
        if res.get("errors"):
            bad = [x for x in res["items"] if x["index"].get("error")][:3]
            print("Bulk errors:", json.dumps(bad, indent=2)); sys.exit(1)
        print(f"Indexed {len(res['items'])} docs")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input"); ap.add_argument("--simulate", type=int)
    ap.add_argument("--out", default="wazuh_alerts.ndjson")
    ap.add_argument("--push", action="store_true")
    ap.add_argument("--host", default="https://localhost:9200")
    ap.add_argument("--user", default="admin"); ap.add_argument("--password", default="admin")
    ap.add_argument("--verify-tls", action="store_true")
    a = ap.parse_args()

    if a.simulate:
        raw = simulate(a.simulate)
    elif a.input:
        raw = open(a.input, encoding="utf-8", errors="replace").read().splitlines()
    else:
        ap.error("use --simulate N or --input FILE")

    docs, skipped = [], 0
    for line in raw:
        ev = parse_cef(line)
        if not ev:
            skipped += 1; continue
        docs.append(to_wazuh(line, ev))
    print(f"Parsed {len(docs)} events, skipped {skipped}")

    with open(a.out, "w") as f:
        f.write("\n".join(bulk_lines(docs)) + "\n")
    print(f"Wrote bulk file: {a.out}")
    print("Sample doc:\n", json.dumps(docs[0][0], indent=2))

    if a.push:
        push(docs, a.host, a.user, a.password, a.verify_tls)


if __name__ == "__main__":
    main()
