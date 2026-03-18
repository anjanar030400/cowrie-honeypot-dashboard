#!/usr/bin/env python3
import json
from collections import Counter
from pathlib import Path
LOG_FILE = Path.home() / "cowrie/var/log/cowrie/cowrie.json"
ip_counter = Counter()
username_counter = Counter()
password_counter = Counter()
command_counter = Counter()
with open(LOG_FILE, "r") as f:
    for line in f:
        try:
            data = json.loads(line)
        except:
            continue
        if "src_ip" in data:
            ip_counter[data["src_ip"]] += 1
        if "username" in data:
            username_counter[data["username"]] += 1
        if "password" in data:
            password_counter[data["password"]] += 1
        if "input" in data:
            command_counter[data["input"]] += 1
print("\nTop IPs:")
for ip, count in ip_counter.most_common(5):
    print(ip, count)
print("\nTop Usernames:")
for user, count in username_counter.most_common(5):
    print(user, count)
print("\nTop Passwords:")
for pw, count in password_counter.most_common(5):
    print(pw, count)
print("\nTop Commands:")
for cmd, count in command_counter.most_common(5):
    print(cmd, count)
