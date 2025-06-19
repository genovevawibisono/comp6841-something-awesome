import sys
import socket
import datetime
import json
import threading

from pathlib import Path

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

class Honeypot:
    def __init__(self, bind_ip="0.0.0.0", ports=None):
        self.bind_ip = bind_ip
        self.ports = ports or [21, 22, 80, 443]
        self.active_connections = {}
        self.log_file = LOG_DIR

    def log_activity(self, port, remote_ip, data):
        pass
