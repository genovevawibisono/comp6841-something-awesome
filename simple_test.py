import unittest
import socket
import time


class HoneypotConnectionTest(unittest.TestCase):
    def setUp(self):
        self.host = "127.0.0.1"
        self.port = 2121
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(3)
        self.sock.connect((self.host, self.port))
        time.sleep(0.1)  # Give honeypot time to send banner

    def tearDown(self):
        self.sock.close()

    def test_banner_and_ftp_login(self):
        banner = self.sock.recv(1024).decode("utf-8", errors="ignore")
        self.assertIn("220", banner)  # Should look like an FTP server

        self.sock.sendall(b"USER testuser\r\n")
        time.sleep(0.1)
        self.sock.sendall(b"PASS testpass\r\n")
        time.sleep(0.1)

        # Optionally read server response
        response = self.sock.recv(1024).decode("utf-8", errors="ignore")
        self.assertTrue(len(response) > 0)

if __name__ == "__main__":
    unittest.main()
