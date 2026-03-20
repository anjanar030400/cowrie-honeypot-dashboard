import streamlit as st
from scripts.parser import parse_log
import matplotlib.pyplot as plt
import pandas as pd
from streamlit_autorefresh import st_autorefresh
st.set_page_config(page_title="Honeypot-Based Threat Intelligence Dashboard", layout="centered")
st_autorefresh(interval=5000, key="honeypot_refresh")
st.title("Honeypot-Based Threat Intelligence Dashboard")
log_file = "/home/student/cowrie/var/log/cowrie/cowrie.json"
data = parse_log(log_file)
col1, col2, col3 = st.columns(3)
col1.metric("Total Commands", sum(data["command_counts"].values()))
col2.metric("Unique Commands", len(data["command_counts"]))
col3.metric("Attack Types", len(data["category_counts"]))
st.markdown("---")
st.subheader("High-Risk Alerts")
alerts = data["high_risk_alerts"]
if alerts:
    for alert in alerts[:5]:
        st.error(
            f"High-risk attacker detected: {alert['src_ip']}"
            f"({alert['country']}) | Score: {alert['score']}"
        )
else:
    st.info("No high-risk attacker sessions detected.")
st.markdown("---")
st.subheader("Live Event Feed")
events = data["live_events"]
if events:
    for event in events[:10]:
        st.markdown(
            f"""
        **Time:** {event['timestamp']} 
        **IP:** `{event['src_ip']}`
        **Country:** {event['country']}  
        **Event:** {event['event']}
        **Details:** {event['details']} 
        **Risk:** {event['risk']} | **Score:** {event['score']}
        """
        )
else:
    st.write("No live events available.")
st.markdown("---")
st.subheader("Threat Scores by IP")
risk_rows = data["ip_risk_table"]
if risk_rows:
    risk_df = pd.DataFrame(risk_rows)
    st.dataframe(risk_df, width="stretch")
else:
    st.write("No IP risk data available")
st.markdown("---")
st.subheader("Top Attacking Countries")
countries = data["country_counts"]
countries_filtered = {k: v for k, v in countries.items() if k != "Local"}
if countries_filtered:
    labels, values = zip(*sorted(countries_filtered.items(), key=lambda x: x[1], reverse=True))
else:
    labels, values = zip(*countries.most_common(10))
fig1, ax1 = plt.subplots()
ax1.bar(labels, values)
plt.xticks(rotation=45)
st.pyplot(fig1)
st.subheader("Top Commands Used by Attackers")
commands = data["command_counts"]
if commands:
    labels, values = zip(*commands.most_common(10))
    fig2, ax2 = plt.subplots()
    ax2.barh(labels, values)
    st.pyplot(fig2)
else:
    st.write("No command data available")

st.subheader("Attack Categories")
categories = data["category_counts"]
if categories:
    labels, values = zip(*categories.most_common())
    fig3, ax3 = plt.subplots()
    ax3.pie(values, labels=labels, autopct='%1.1f%%')
    st.pyplot(fig3)
else:
    st.write("No category data available")
st.subheader("Attack Activity Over Time")
timestamps = data["time_data"]
if timestamps:
    df = pd.DataFrame({"timestamp": timestamps})
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["hour"] = df["timestamp"].dt.hour
    hourly = df.groupby("hour").size().reindex(range(24), fill_value=0)
    fig4, ax4 = plt.subplots()
    ax4.plot(hourly.index, hourly.values, marker='o')
    ax4.set_xlabel("Hour of Day (0-23)")
    ax4.set_ylabel("Number of Attacks")
    ax4.set_title("Attacks by Hour")
    ax4.set_xticks(range(0, 24, 2))
    st.pyplot(fig4)
    st.caption("Number of attacks per hour (0-23)")
    peak_hour = hourly.idxmax()
    st.success(f"Peak attack activity observed at hour {peak_hour:02d}:00 hours")
else:
    st.write("No time data available")
#---------------INSIGHTS-----------
st.subheader("Key Insights")
st.write("""
- Attackers commonly run reconnaissance commands like 'whoami', 'uname', and 'ls'
- Attempts to access '/etc/passwd' indicate credential harvesting
- Use of 'wget' suggests malware download attempts
- Current traffic is local ( likely testing environment)
""")
