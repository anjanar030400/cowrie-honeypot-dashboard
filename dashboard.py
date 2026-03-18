import json
from pathlib import Path
from collections import Counter
import pandas as pd
import streamlit as st
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
ip_df = pd.DataFrame(ips.most_common(10), columns=["IP", "Count"])
cmd_df = pd.DataFrame(commands.most_common(10), columns=["Command", "Count"])
st.title("Honeypot Threat Dashboard")
st.subheader("Top Attacker IPs")
st.dataframe(ip_df)
st.subheader("Top Commands")
st.dataframe(cmd_df)
st.subheader("Command Frequency Chart")
st.bar_chart(cmd_df.set_index("Command"))
