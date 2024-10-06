import json
import logging
import socket
from datetime import datetime
from scapy.all import IP, TCP, UDP
import pydivert

# error log configs
logging.basicConfig(
    filename='firewall_error.log',
    level=logging.ERROR,
    format='%(asctime)s %(levelname)s:%(message)s'
)

# loading the policies
def load_policies():
    try:
        with open('policies.json', 'r') as file:
            policies = json.load(file)
            return policies.get('rules', [])
    except Exception as e:
        logging.error(f"Failed to load policies: {e}")
        return []

# domain to IP conversion
def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        logging.error(f"Failed to resolve domain {domain}: {e}")
        return None

# IP to Domain conversion
def resolve_ip_to_domain(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

# Check packet matching any policy
def check_policies(packet_info, policies):
    for rule in policies:
        match = True

        # IP
        if 'ip' in rule and rule['ip']:
            if packet_info['ip'] != rule['ip']:
                match = False

        # Domain
        if 'domain' in rule and rule['domain']:
            if packet_info['domain'] != rule['domain']:
                match = False

        # Protocol
        if 'protocol' in rule and rule['protocol']:
            if packet_info['protocol'].upper() != rule['protocol'].upper():
                match = False

        # Port
        if 'port' in rule and rule['port']:
            if packet_info['port'] != rule['port']:
                match = False

        if match:
            return rule['action'].upper(), rule['name']
    return 'ALLOW', None

# save packet info
def log_packet(packet_info, action, rule_name=None):
    pass    #somnath

# check packet
def process_packet():
    pass    # Debleena(scapy use korbi)

# Start packet filtering
def start_firewall():
    policies = load_policies()
    with pydivert.WinDivert("true") as w:
        for packet in w:
            if process_packet(packet, policies):
                w.send(packet)  # Forward packet

if __name__ == "__main__":
    start_firewall()
