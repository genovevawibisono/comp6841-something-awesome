import sys
import socket
import datetime
import json
import threading

import os

import argparse
from concurrent.futures import ThreadPoolExecutor
import time

import random

import requests

from pathlib import Path

from collections import defaultdict

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

class Honeypot:
    def __init__(self, bind_ip="0.0.0.0", ports=None):
        self.bind_ip = bind_ip
        self.ports = ports or [2121, 2222, 8080, 8443]
        self.active_connections = {}
        self.log_file = LOG_DIR / f"log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
        self.failed_attempts = defaultdict()
        self.alert_threshold = 5

    def log_activity(self, port, remote_ip, data):
        print(f"[LOGGING] {remote_ip}:{port} -> {data}")
        geo_info = self.geoip_logging(remote_ip)
        activity = {
            "timestamp": datetime.datetime.now().isoformat(),
            "remote_ip": remote_ip,
            "port": port,
            "geo": geo_info,
            "data": data.decode('utf-8', errors='ignore')
        }

        with open(self.log_file, "a") as opened_log_file:
            json.dump(activity, opened_log_file)
            opened_log_file.write("\n")

    def handle_connection(self, client_socket, remote_ip, port):
        service_banners = {
            2121: [
                "220 ProFTPD 1.3.6 Server (Debian) [::ffff:127.0.0.1]\r\n",
                "220 (vsFTPd 3.0.3)\r\n"
            ],
            2222: [
                "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
                "SSH-2.0-OpenSSH_7.4\r\n",
                "SSH-2.0-Dropbear_2022.82\r\n"
            ],
            8080: [
                "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n",
                "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\n\r\n"
            ],
            8443: [
                "HTTP/1.1 200 OK\r\nServer: Apache/2.4.46 (Debian)\r\n\r\n",
                "HTTP/1.1 200 OK\r\nServer: nginx/1.14.2 (Debian)\r\n\r\n"
            ]
        }

        try:
            if port in service_banners:
                banner = random.choice(service_banners[port])
                client_socket.send(banner.encode())

            if port == 2222:
                self.fake_ssh_shell(client_socket, remote_ip, port)
                return
            
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                self.log_activity(port, remote_ip, data)
                client_socket.send(b"Command not recognized.\r\n")
        except Exception as e:
            print(f"Error in handling connection: {e}")
        finally:
            client_socket.close()

    def geoip_logging(self, ip):
        try:
            response = requests.get(f"https://ipapi.co/{ip}/json/")
            if response.status_code == 200:
                data = response.json()
                return {
                    "country": data.get("country_name"),
                    "region": data.get("region"),
                    "city": data.get("city"),
                    "org": data.get("org")
                }
        except Exception as e:
            print(f"GeoIP lookup failed: {e}")
        return {}
    
    def fake_ssh_shell(self, client_socket, remote_ip, port):
        try:
            client_socket.send(b"login: ")
            username = client_socket.recv(1024).decode('utf-8', 'ignore').strip()

            client_socket.send(b"Password: ")
            password = client_socket.recv(1024).decode('utf-8', 'ignore').strip()

            self.log_activity(port, remote_ip, f"SSH login attempt: {username}:{password}".encode())

            client_socket.send(b"Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-26-generic x86_64)\n")
            client_socket.send(b"$ ")

            fake_outputs = {
                "ls": "bin  boot  dev  etc  home  lib  tmp  usr  var\n",
                "pwd": "/home/fakeuser\n",
                "whoami": "fakeuser\n",
                "cat flag.txt": "Access Denied\n"
            }

            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                command = data.decode('utf-8', 'ignore').strip()

                self.failed_attempts[remote_ip] += 1

                self.log_activity(port, remote_ip, f"Shell command: {command}".encode())

                if self.failed_attempts[remote_ip] >= self.alert_threshold:
                    self.raise_brute_force_alert(remote_ip, port)

                response = fake_outputs.get(command, "Command not found\n")
                client_socket.send(response.encode())
                client_socket.send(b"$ ")
        except Exception as e:
            print(f"Error in fake SSH shell: {e}")

    def raise_brute_force_alert(self, remote_ip, port):
        alert_message = (
            f"[ALERT] Brute-force detected from {remote_ip} on port {port} "
            f"with {self.failed_attempts[remote_ip]} attempts."
        )
        print(alert_message)

        with open(LOG_DIR / "alerts.log", "a") as alert_file:
            alert_file.write(f"{datetime.datetime.now().isoformat()} - {alert_message}\n")

class NetworkListener:
    def __init__(self, bind_ip, honeypot):
        self.bind_ip = bind_ip
        self.honeypot = honeypot

    def listen(self, port):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind((self.bind_ip, port))
            server.listen(5)

            print(f"Listening on bind ip: {self.bind_ip}, port: {port}\n")

            while True:
                client, address = server.accept()
                print(f"[*] Accepted connection from: {address[0]}:{address[1]}")
                client_handler = threading.Thread(target=self.honeypot.handle_connection, args=(client, address[0], port))
                client_handler.start()
        except Exception as e:
            print(f"Error in network listener: {e}")
    
class Simulator:
    def __init__(self, target_ip="127.0.0.1", intensity="medium"):
        self.target_ip = target_ip
        self.intensity = intensity
        self.target_ports = [2121, 2222, 8080, 8443, 3306, 5432]
        self.attack_patterns = {
            2121: [
                "USER admin\r\n",
                "PASS admin_password\r\n",
                "LIST\r\n",
                "STOR malware.exe\r\n"
            ],
            2222: [
                "SSH-2.0-OpenSSH_7.9\r\n",
                "admin:admin_password\r\n",
                "root:root\r\n"
            ],
            8080: [
                "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                "POST /admin HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
                "GET /wp-admin HTTP/1.1\r\nHost: localhost\r\n\r\n"
            ]
        }
        self.intensity_settings = {
            "low": {
                "max_threads": 2,
                "delay_range": (1, 3)
            },
            "medium": {
                "max_threads": 5,
                "delay_range": (0.5, 1.5)
            },
            "high": {
                "max_threads": 10,
                "delay_range": (0.25, 0.75)
            }
        }

    def simulate_connection(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            print(f"[*] Attempting to connect to {self.target_ip}:{port}")

            sock.connect((self.target_ip, port))
            banner = sock.recv(1024)
            print(f"Received banner from port {port}:{banner.decode('utf-8', 'ignore').strip()}")

            if port in self.attack_patterns:
                for command in self.attack_patterns[port]:
                    print(f"Sending command to port {port}: {command.strip()}")
                    sock.send(command.encode())
                    try:
                        response = sock.recv(1024)
                        print(f"Received response: {response.decode('utf-8', 'ignore').strip()}")
                    except socket.timeout:
                        print(f"Socket timed out in simulate connection function")
            sock.close()
        except ConnectionRefusedError:
            print("Connection refused - simulate connection function")
        except socket.timeout:
            print("Socket timed out - simulate connection function")
        except Exception as e:
            print(f"Error in simulating connection: {e}\n")

    def simulate_port_scan(self):
        print("Starting simulate port scan - Simulator")
        for port in self.target_ports:
            self.simulate_connection(port)
            time.sleep(random.uniform(0.1, 0.3))

    def load_from_file(self, filename):
        if not os.path.exists(filename):
            print("File does not exist")
            return []
        
        try:
            with open(filename) as f:
                values = [line.strip() for line in f if line.strip()]
            return values
        except Exception as e:
            print(f"Error in load from file function: {e}\n")
            return []

    def simulate_brute_force(self, port):
        common_usernames = self.load_from_file("common_usernames.txt")
        if not common_usernames:
            print("No common usernames loaded")
            return
        
        common_passwords = self.load_from_file("common_passwords.txt")
        if not common_passwords:
            print("No common passwords loaded")
            return
        
        print(f"Starting brute force attack on port: {port}")

        for username in common_usernames:
            for password in common_passwords:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((self.target_ip, port))

                    if port == 21:
                        sock.send(f"USER {username}\r\n".encode())
                        sock.recv(1024)
                        sock.send(f"PASS {password}\r\n".encode())
                    elif port == 22:
                        sock.send(f"{username}:{password}\r\n".encode())

                    sock.close()
                    time.sleep(random.uniform(0.1, 0.3))
                except Exception as e:
                    print(f"Error in brute force attack simulation: {e}")

    def run_continuous_simulation(self, duration=300):
        end_time = time.time() + duration

        with ThreadPoolExecutor(
            max_workers=self.intensity_settings[self.intensity]["max_threads"]
        ) as executor:
            while time.time() < end_time:
                simulation_choices = [
                    lambda: self.simulate_port_scan(),
                    lambda: self.simulate_brute_force(2121),
                    lambda: self.simulate_brute_force(2222),
                    lambda: self.simulate_connection(8080)
                ]

                executor.submit(random.choice(simulation_choices))
                time.sleep(random.uniform(*self.intensity_settings[self.intensity]["delay_range"]))

if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["honeypot", "simulate"], required=True)
    parser.add_argument("--ip", default="0.0.0.0")
    parser.add_argument("--intensity", choices=["low", "medium", "high"], default="medium")
    args = parser.parse_args()

    if args.mode == "honeypot":
        honeypot_object = Honeypot(bind_ip=args.ip)
        network_listener_object = NetworkListener(bind_ip=args.ip, honeypot=honeypot_object)
        for port in honeypot_object.ports:
            threading.Thread(target=network_listener_object.listen, args=(port,), daemon=True).start()
            while True:
                time.sleep(1)
    elif args.mode == "simulate":
        simulator_object = Simulator(target_ip=args.ip, intensity=args.intensity)
        simulator_object.run_continuous_simulation()
