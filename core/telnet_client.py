#!/usr/bin/env python3
"""
ZTE F6107A Telnet & Command Execution Engine.
Handles port probing, authentication, ZTE restricted menu bypass (Ctrl+C),
and DB command execution (`sendcmd 1 DB ...`).
"""

import socket
import time
import re

class TelnetClient:
    @staticmethod
    def probe_port(ip, port, timeout=1.0):
        try:
            s = socket.create_connection((ip, port), timeout=timeout)
            s.close()
            return True
        except Exception:
            return False

    @classmethod
    def probe_http(cls, ip="192.168.1.1", timeout=1.0):
        return cls.probe_port(ip, 80, timeout=timeout)

    @classmethod
    def probe_telnet(cls, ip="192.168.1.1", timeout=1.0):
        return cls.probe_port(ip, 23, timeout=timeout)

    @classmethod
    def get_candidate_creds(cls, username="root", password="admin"):
        """Returns list of candidate credentials for Telnet login attempts."""
        candidate_creds = [(username, password)]
        if (username, password) != ("root", "admin"):
            candidate_creds.append(("root", "admin"))
        if (username, password) != ("root", "!@#$%12345"):
            candidate_creds.append(("root", "!@#$%12345"))
        if (username, password) != ("root", "root"):
            candidate_creds.append(("root", "root"))
        return candidate_creds

    @classmethod
    def create_session(cls, ip, username, password, max_retries=3):
        """Connects to Telnet, authenticates, escapes the restricted menu, and returns (sock, run_cmd_fn)."""
        candidate_creds = cls.get_candidate_creds(username, password)

        sock = None
        for attempt in range(1, max_retries + 1):
            for u, p in candidate_creds:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5.0)
                try:
                    s.connect((ip, 23))
                    buf = b""
                    while b"login:" not in buf.lower():
                        chunk = s.recv(1024)
                        if not chunk:
                            break
                        buf += chunk

                    s.sendall(u.encode() + b"\r\n")
                    time.sleep(0.3)

                    buf = b""
                    while b"password:" not in buf.lower():
                        chunk = s.recv(1024)
                        if not chunk:
                            break
                        buf += chunk

                    s.sendall(p.encode() + b"\r\n")
                    time.sleep(0.5)

                    # Send Ctrl+C to break out of ZTE PLOAM menu
                    s.sendall(b"\x03\r\n")
                    time.sleep(0.3)

                    # Read banner
                    s.setblocking(False)
                    banner = b""
                    try:
                        time.sleep(0.3)
                        banner = s.recv(4096)
                    except Exception:
                        pass
                    s.setblocking(True)
                    s.settimeout(10.0)

                    if b"#" in banner or b"$" in banner or b"root@" in banner or b"F6107A" in banner:
                        sock = s
                        break
                    
                    # Try sending Ctrl+C again
                    s.sendall(b"\x03\r\n")
                    time.sleep(0.3)
                    s.setblocking(False)
                    try:
                        time.sleep(0.3)
                        banner += s.recv(4096)
                    except Exception:
                        pass
                    s.setblocking(True)
                    s.settimeout(10.0)

                    if b"#" in banner or b"$" in banner or b"root@" in banner or b"F6107A" in banner:
                        sock = s
                        break
                    s.close()
                except Exception as e:
                    s.close()
                    if "Connection refused" in str(e):
                        raise e
                    continue
            if sock:
                break
            time.sleep(1.0)

        if not sock:
            raise RuntimeError(f"Could not connect or authenticate to Telnet at {ip}:23")

        def run_cmd(cmd_str, timeout=45.0):
            sock.sendall(cmd_str.strip().encode() + b"\r\n")
            time.sleep(0.4)
            resp = b""
            sock.settimeout(timeout)
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if b"root@F6107A" in resp or b"# " in resp or b"$ " in resp:
                        break
                except socket.timeout:
                    break
            return resp.decode("latin-1", errors="ignore")

        return sock, run_cmd
