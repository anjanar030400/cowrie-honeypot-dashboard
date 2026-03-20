import json
import geoip2.database
from collections import Counter, defaultdict
import ipaddress
reader = geoip2.database.Reader("/home/student/honeypot-project/GeoLite2-City.mmdb")
def get_country(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            return "Local"
        response = reader.city(ip)
        return response.country.name
    except Exception:
        return "Unknown"
def categorize_command(cmd):
    cmd = cmd.lower()
    if any(x in cmd for x in ["whoami", "uname", "ls", "pwd"]):
        return "Recon"
    elif "/etc/passwd" in cmd:
        return "Credential Access"
    elif "wget" in cmd or "curl" in cmd:
        return "Malware Download"
    else:
        return "Other"
def score_command(cmd):
    cmd = cmd.lower()
    if any(x in cmd for x in ["whoami", "uname", "ls", "pwd"]):
        return 1
    elif "/etc/passwd" in cmd:
        return 4
    elif "wget" in cmd or "curl" in cmd:
        return 5
    elif "chmod" in cmd or "./" in cmd:
        return 4
    else:
        return 2
def risk_level(score):
    if score >= 8:
        return "High"
    elif score >= 4:
        return "Medium"
    return "Low"
def parse_log(file_path):
    countries = []
    commands = []
    categories = []
    timestamps = []
    ip_scores = defaultdict(int)
    ip_commands = defaultdict(list)
    live_events = []
    with open(file_path, "r") as f:
        for line in f:
            try:
                log = json.loads(line)
                timestamp = log.get("timestamp", "Unknown time")
                src_ip = log.get("src_ip", "Unknown IP")
                eventid = log.get("eventid", "unknown")
                if "timestamp" in log:
                    timestamps.append(log["timestamp"])
                if "src_ip" in log:
                    countries.append(get_country(src_ip))
                if "input" in log:
                    cmd = log["input"]
                    commands.append(cmd)
                    category = categorize_command(cmd)
                    categories.append(category)
                    score = score_command(cmd)
                    ip_scores[src_ip] += score
                    ip_commands[src_ip].append(cmd)
                    live_events.append({
                        "timestamp": timestamp,
                        "src_ip": src_ip,
                        "country": get_country(src_ip),
                        "event": "command",
                        "details": cmd,
                        "score": ip_scores[src_ip],
                        "risk": risk_level(ip_scores[src_ip]),
                    })
                elif eventid == "cowrie.login.failed":
                    ip_scores[src_ip] += 1
                    live_events.append({
                        "timestamp": timestamp,
                        "src_ip": src_ip,
                        "country": get_country(src_ip),
                        "event": "login_failed",
                        "details": "Failed login attempt",
                        "score": ip_scores[src_ip],
                        "risk": risk_level(ip_scores[src_ip]),
                    })
                elif eventid == "cowrie.login.success":
                    ip_scores[src_ip] += 2
                    live_events.append({
                        "timestamp": timestamp,
                        "src_ip": src_ip,
                        "country": get_country(src_ip),
                        "event": "login_success",
                        "details": "Successful login",
                        "score": ip_scores[src_ip],
                        "risk": risk_level(ip_scores[src_ip]),
                    })
            except json.JSONDecodeError:
                continue
    ip_risk_table = []
    for ip, score in ip_scores.items():
        ip_risk_table.append({
            "src_ip": ip,
            "country": get_country(ip),
            "score": score,
            "risk": risk_level(score),
            "commands_seen": len(ip_commands[ip]),
        })
    ip_risk_table = sorted(ip_risk_table, key=lambda x: x["score"], reverse=True)
    live_events = sorted(live_events, key=lambda x:x["timestamp"], reverse=True)
    return {
        "country_counts": Counter(countries),
        "command_counts": Counter(commands),
        "category_counts": Counter(categories),
        "time_data": timestamps,
        "ip_risk_table": ip_risk_table,
        "live_events": live_events[:20],
        "high_risk_alerts": [x for x in ip_risk_table if x["risk"] == "High"],
    }
if __name__ == "__main__":
    log_file = "/home/student/cowrie/var/log/cowrie/cowrie.json"
    result = parse_log(log_file)
    print("Top Countries:")
    print(result["country_counts"].most_common(10))
    print("\nTop Commands:")
    print(result["command_counts"].most_common(10))
    print("\nTop Categories:")
    print(result["category_counts"].most_common(10))
    print("\nIP Risk Table:")
    print(result["ip_risk_table"][:5])
    print("\nLive Events:")
    print(result["live_events"][:5])
