#!/usr/bin/env python3
"""
ZTE F6107A Factory Mode Challenge-Response Engine.
Handles Protocol v1 and v2 handshakes, dynamic AES key derivation, and authentication.
Compatible with PON_2.0 and PON_6.0.
"""

import time
import requests
from random import Random
from urllib.parse import urlparse, parse_qs
from Crypto.Cipher import AES

def pad(d, b=16): return d + b'\x00' * (b - len(d) % b)
def unpad(p, b=16):
    if len(p) < b: return p.rstrip(b'\x00')
    return p[:-b] + p[-b:].rstrip(b'\x00')

def safe_decrypt(cipher, data, b=16):
    if not data or len(data) % b != 0:
        return b""
    try:
        return unpad(cipher.decrypt(data), b)
    except Exception:
        return b""

class FactoryModeClient:
    AES_KEY_POOL_V1 = [
        0x7B, 0x56, 0xB0, 0xF7, 0xDA, 0x0E, 0x68, 0x52, 0xC8, 0x19,
        0xF3, 0x2B, 0x84, 0x90, 0x79, 0xE5, 0x62, 0xF8, 0xEA, 0xD2,
        0x64, 0x93, 0x87, 0xDF, 0x73, 0xD7, 0xFB, 0xCC, 0xAA, 0xFE,
        0x75, 0x43, 0x1C, 0x29, 0xDF, 0x4C, 0x52, 0x2C, 0x6E, 0x7B,
        0x45, 0x3D, 0x1F, 0xF1, 0xDE, 0xBC, 0x27, 0x85, 0x8A, 0x45,
        0x91, 0xBE, 0x38, 0x13, 0xDE, 0x67, 0x32, 0x08, 0x54, 0x11,
        0x75, 0xF4, 0xD3, 0xB4, 0xA4, 0xB3, 0x12, 0x86, 0x67, 0x23,
        0x99, 0x4C, 0x61, 0x7F, 0xB1, 0xD2, 0x30, 0xDF, 0x47, 0xF1,
        0x76, 0x93, 0xA3, 0x8C, 0x95, 0xD3, 0x59, 0xBF, 0x87, 0x8E,
        0xF3, 0xB3, 0xE4, 0x76, 0x49, 0x88
    ]

    AES_KEY_POOL_V2 = [
        0x8C, 0x23, 0x65, 0xD1, 0xFC, 0x32, 0x45, 0x37, 0x11, 0x28,
        0x71, 0x63, 0x07, 0x20, 0x69, 0x14, 0x73, 0xE7, 0xD4, 0x53,
        0x13, 0x24, 0x36, 0xC2, 0xB5, 0xE1, 0xFC, 0xCF, 0x8A, 0x9A,
        0x41, 0x89, 0x3C, 0x49, 0xCF, 0x5C, 0x72, 0x8C, 0x9E, 0xEB,
        0x75, 0x0D, 0x3F, 0xD1, 0xFE, 0xCC, 0x57, 0x65, 0x7A, 0x35,
        0x21, 0x3E, 0x68, 0x53, 0x7E, 0x97, 0x02, 0x48, 0x74, 0x71,
        0x95, 0x34, 0x53, 0x84, 0xB4, 0xC3, 0xE2, 0xD6, 0x27, 0x3D,
        0xE6, 0x5D, 0x72, 0x9C, 0xBC, 0x3D, 0x03, 0xFD, 0x76, 0xC1,
        0x9C, 0x25, 0xA8, 0x92, 0x47, 0xE4, 0x18, 0x0F, 0x24, 0x3F,
        0x4F, 0x67, 0xEC, 0x97, 0xF4, 0x99
    ]

    CREDENTIAL_CANDIDATES = [
        ("awnfibre", "fibre@dm!n"),
        ("admin", "aisadmin"),
        ("factorymode", "nE%jA@5b"),
    ]

    @classmethod
    def negotiate(cls, ip="192.168.1.1", port=80, timeout=5, max_retries=3):
        """Performs full Factory Mode negotiation and returns (username, password), matched_user, proto_version."""
        last_err = None
        for attempt in range(1, max_retries + 1):
            session = requests.Session()
            try:
                try: session.post(f"http://{ip}:{port}/webFac", data='SendSq.gch', timeout=2)
                except Exception: pass

                try: session.post(f"http://{ip}:{port}/webFac", data='RequestFactoryMode.gch', timeout=2)
                except Exception: pass

                time.sleep(0.4)

                rand = Random().randint(0, 59)
                resp = session.post(f"http://{ip}:{port}/webFac", data=f'SendSq.gch?rand={rand}\r\n', timeout=timeout)
                if resp.status_code != 200:
                    raise RuntimeError(f"SendSq rejected with status {resp.status_code}")

                if "newrand=" in resp.text:
                    newrand = int(resp.text[len("newrand="):])
                    index = ((0x1000193 * rand) & 0x3F ^ newrand) % 60
                    key_pool = cls.AES_KEY_POOL_V2
                    proto_ver = 2
                else:
                    index = rand
                    key_pool = cls.AES_KEY_POOL_V1
                    proto_ver = 1

                key = bytes(map(lambda x: (x ^ 0xA5) & 0xFF, key_pool[index:index+24]))
                cipher = AES.new(key, AES.MODE_ECB)

                if proto_ver == 2:
                    session.post(f"http://{ip}:{port}/webFacEntry", 
                                 data=cipher.encrypt(pad(b'SendInfo.gch?info=6|')), timeout=timeout)

                authenticated = False
                used_user = ""
                for user, pwd in cls.CREDENTIAL_CANDIDATES:
                    payload = f'CheckLoginAuth.gch?version50&user={user}&pass={pwd}'.encode()
                    try:
                        r = session.post(f"http://{ip}:{port}/webFacEntry", 
                                         data=cipher.encrypt(pad(payload)), timeout=timeout)
                        if r.status_code == 200:
                            dec = safe_decrypt(cipher, r.content)
                            if b'FactoryMode.gch' in dec:
                                authenticated = True
                                used_user = user
                                break
                    except Exception:
                        continue

                if not authenticated:
                    raise RuntimeError("Authentication rejected for all candidate credentials.")

                # Request credentials (Try modes: 2, 3, 1, 0)
                for m in [2, 3, 1, 0]:
                    payload = f'FactoryMode.gch?mode={m}&user=notused'.encode()
                    try:
                        r = session.post(f"http://{ip}:{port}/webFacEntry", 
                                         data=cipher.encrypt(pad(payload)), timeout=timeout)
                        if r.status_code == 200:
                            dec = safe_decrypt(cipher, r.content).decode('ascii', errors='replace').rstrip('\x00')
                            if "user=" in dec and "pass=" in dec:
                                parsed = parse_qs(urlparse(dec).query)
                                return (parsed['user'][0], parsed['pass'][0]), used_user, proto_ver
                    except Exception:
                        continue

                raise RuntimeError("Failed to obtain Telnet credentials from FactoryMode.")
            except Exception as e:
                last_err = e
                if attempt < max_retries:
                    time.sleep(1.0)

        raise RuntimeError(f"Factory Mode negotiation failed after {max_retries} attempts: {last_err}")
