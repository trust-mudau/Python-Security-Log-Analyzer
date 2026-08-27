from collections import defaultdict
from pathlib import Path
import sys, json

THRESHOLD = 5

def parse_line(line):
    parts = line.strip().split()
    if len(parts) < 5:
        return None
    date, time, event, ip, user = parts[:5]
    return {"timestamp": f"{date} {time}", "event": event, "ip": ip, "user": user}

def analyze(path):
    failures_by_ip = defaultdict(list)
    failures_by_user = defaultdict(list)
    successes = []
    records = []

    for line in Path(path).read_text(encoding="utf-8").splitlines():
        rec = parse_line(line)
        if not rec:
            continue
        records.append(rec)
        if rec["event"] == "LOGIN_FAILED":
            failures_by_ip[rec["ip"]].append(rec)
            failures_by_user[rec["user"]].append(rec)
        elif rec["event"] == "LOGIN_SUCCESS":
            successes.append(rec)

    alerts = []

    for ip, events in failures_by_ip.items():
        if len(events) >= THRESHOLD:
            alerts.append({
                "type": "Repeated failed logins",
                "severity": "HIGH",
                "source_ip": ip,
                "count": len(events)
            })

    for success in successes:
        prior = [x for x in failures_by_ip.get(success["ip"], []) if x["timestamp"] <= success["timestamp"]]
        if len(prior) >= THRESHOLD:
            alerts.append({
                "type": "Successful login after repeated failures",
                "severity": "HIGH",
                "source_ip": success["ip"],
                "user": success["user"],
                "prior_failures": len(prior)
            })

    return {"records_analyzed": len(records), "alerts": alerts}

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyzer.py <logfile>")
        raise SystemExit(1)
    result = analyze(sys.argv[1])
    print(json.dumps(result, indent=2))
