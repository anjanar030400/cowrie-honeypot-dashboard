import json
from pathlib import Path
from collections import Counter
import matplotlib.pyplot as plt
LOG = Path.home() / "cowrie/var/log/cowrie/cowrie.json"
ips = Counter()
commands = Counter()
with open(LOG, "r") as f:
    for line in f:
        try:
            data = json.loads(line)
        except:
            continue
        if "src_ip" in data:
            ips[data["src_ip"]] += 1
        if "input" in data:
            commands[data["input"]] += 1
print("\nTop IPs:")
for ip, count in ips.most_common(5):
    print(ip, count)
print("\nTop Commands:")
for cmd, count in commands.most_common(5):
    print(cmd, count)
labels = [cmd for cmd, _ in commands.most_common(5)]
values = [count for _, count in commands.most_common(5)]
plt.figure(figsize=(8, 5))
plt.bar(labels, values)
plt.xticks(rotation=30)
plt.title("Top Attacker Commands")
plt.ylabel("Frequency")
plt.xlabel("Commands")
plt.tight_layout()
plt.savefig("commands.png")
