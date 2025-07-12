import socket
import time
import argparse
import threading

from app import Honeypot, NetworkListener, Simulator

def test_brute_force_simulation(target_ip="127.0.0.1", port=22, attempts=6):
    """
    Simulates repeated SSH login attempts to test brute-force alerting.
    """
    print(f"\n[TEST] Starting brute-force test with {attempts} attempts on {target_ip}:{port}")

    for i in range(attempts):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target_ip, port))

            # Receive the SSH banner
            sock.recv(1024)

            # Send fake username
            sock.sendall(b"admin\n")
            time.sleep(0.1)  # wait for "Password:"

            # Send fake password
            sock.sendall(b"password123\n")
            time.sleep(0.2)

            print(f"[TEST] Attempt {i+1} sent.")

            sock.close()
        except Exception as e:
            print(f"[TEST ERROR] Attempt {i+1} failed: {e}")
        time.sleep(0.3)  # small delay between attempts

    print("[TEST] Brute-force test completed.\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["honeypot", "simulate", "test"], required=True)
    parser.add_argument("--ip", default="0.0.0.0")
    args = parser.parse_args()

    if args.mode == "honeypot":
        honeypot_object = Honeypot(bind_ip=args.ip)
        network_listener_object = NetworkListener(bind_ip=args.ip, honeypot=honeypot_object)
        for port in honeypot_object.ports:
            threading.Thread(target=network_listener_object.listen, args=(port,), daemon=True).start()
        while True:
            time.sleep(1)

    elif args.mode == "simulate":
        simulator_object = Simulator(target_ip=args.ip)
        simulator_object.run_continuous_simulation()

    elif args.mode == "test":
        test_brute_force_simulation(target_ip=args.ip)

