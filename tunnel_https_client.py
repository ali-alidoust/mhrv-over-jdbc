import mysql.connector
import base64
import json
import ssl
import os

class TunnelSocket:
    def __init__(self, host, port, auth_key, tunnel_host, tunnel_port):
        self.host = host
        self.port = port
        self.auth_key = auth_key
        self.tunnel_host = tunnel_host
        self.tunnel_port = tunnel_port
        self.eof = False
        self.conn = mysql.connector.connect(
            host=tunnel_host,
            port=tunnel_port,
            user="any_user",
            password="any_password",
            database=None,
            connection_timeout=10,
            ssl_disabled=True
        )
        self.cursor = self.conn.cursor()
        self.sid = self._connect()

    def _connect(self):
        payload = {"op": "connect", "host": self.host, "port": self.port}
        if self.auth_key:
            payload["k"] = self.auth_key
        payload_json = json.dumps(payload)
        payload_b64 = base64.b64encode(payload_json.encode("utf-8")).decode("utf-8")
        query = f"SELECT MHRV_TUNNEL('{payload_b64}')"
        self.cursor.execute(query)
        result = self.cursor.fetchone()
        if not (result and isinstance(result, (tuple, list)) and isinstance(result[0], str)):
            raise RuntimeError("Tunnel connect failed")
        result_json = base64.b64decode(result[0]).decode("utf-8")
        response = json.loads(result_json)
        if "sid" not in response:
            raise RuntimeError(f"Tunnel connect error: {response}")
        return response["sid"]

    def send(self, data):
        payload = {
            "op": "data",
            "sid": self.sid,
            "d": base64.b64encode(data).decode("utf-8")
        }
        if self.auth_key:
            payload["k"] = self.auth_key
        payload_json = json.dumps(payload)
        payload_b64 = base64.b64encode(payload_json.encode("utf-8")).decode("utf-8")
        query = f"SELECT MHRV_TUNNEL('{payload_b64}')"
        self.cursor.execute(query)
        _ = self.cursor.fetchone()
        self.cursor.fetchall()
        while self.cursor.nextset():
            self.cursor.fetchall()
        # Ignore response; use recv to get data

    def recv(self, bufsize=4096, timeout=2.0):
        import time
        if self.eof:
            return b""
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            payload = {
                "op": "data",
                "sid": self.sid
            }
            if self.auth_key:
                payload["k"] = self.auth_key
            payload_json = json.dumps(payload)
            payload_b64 = base64.b64encode(payload_json.encode("utf-8")).decode("utf-8")
            query = f"SELECT MHRV_TUNNEL('{payload_b64}')"
            self.cursor.execute(query)
            result = self.cursor.fetchone()
            self.cursor.fetchall()
            while self.cursor.nextset():
                self.cursor.fetchall()
            if result and isinstance(result, (tuple, list)) and isinstance(result[0], str):
                result_json = base64.b64decode(result[0]).decode("utf-8")
                response = json.loads(result_json)
                if "d" in response:
                    return base64.b64decode(response["d"])
                if response.get("eof"):
                    self.eof = True
                    return b""
            time.sleep(0.05)
        return b""

    def close(self):
        payload = {"op": "close", "sid": self.sid}
        if self.auth_key:
            payload["k"] = self.auth_key
        payload_json = json.dumps(payload)
        payload_b64 = base64.b64encode(payload_json.encode("utf-8")).decode("utf-8")
        query = f"SELECT MHRV_TUNNEL('{payload_b64}')"
        self.cursor.execute(query)
        self.conn.close()

    # For ssl.wrap_socket compatibility
    def settimeout(self, timeout):
        pass
    def fileno(self):
        return -1

def fetch_https_page(host, path="/", tunnel_host="127.0.0.1", tunnel_port=3306, auth_key=None):
    import ssl
    import time
    sock = TunnelSocket(host, 443, auth_key, tunnel_host, tunnel_port)
    context = ssl.create_default_context()
    in_bio = ssl.MemoryBIO()
    out_bio = ssl.MemoryBIO()
    ssl_obj = context.wrap_bio(in_bio, out_bio, server_hostname=host)
    # Perform handshake
    while True:
        try:
            ssl_obj.do_handshake()
            break
        except ssl.SSLWantReadError:
            out = out_bio.read()
            if out:
                sock.send(out)
            in_data = sock.recv(4096)
            if in_data:
                in_bio.write(in_data)
            else:
                time.sleep(0.05)
        except ssl.SSLWantWriteError:
            out = out_bio.read()
            if out:
                sock.send(out)
    # Send HTTP request
    request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("utf-8")
    ssl_obj.write(request)
    # Send any pending SSL data
    out = out_bio.read()
    if out:
        sock.send(out)
    response = b""
    eof = False
    while not eof:
        try:
            chunk = ssl_obj.read(4096)
            if not chunk:
                break
            response += chunk
        except ssl.SSLWantReadError:
            out = out_bio.read()
            if out:
                sock.send(out)
            in_data = sock.recv(4096)
            if in_data:
                in_bio.write(in_data)
            else:
                # If no data and sock.eof, break to avoid hanging
                if sock.eof:
                    eof = True
                else:
                    time.sleep(0.05)
        except ssl.SSLWantWriteError:
            out = out_bio.read()
            if out:
                sock.send(out)
    # Attempt to shutdown SSL cleanly to flush any remaining data
    try:
        ssl_obj.unwrap()
    except Exception:
        pass
    sock.close()
    return response.decode("utf-8", errors="replace")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Fetch HTTPS page via MHRV tunnel")
    parser.add_argument("--tunnel-host", default="127.0.0.1")
    parser.add_argument("--tunnel-port", type=int, default=3306)
    parser.add_argument("--auth-key", default=os.getenv("TUNNEL_AUTH_KEY"))
    parser.add_argument("--host", required=True)
    parser.add_argument("--path", default="/")
    args = parser.parse_args()

    print(f"Fetching https://{args.host}{args.path} via tunnel {args.tunnel_host}:{args.tunnel_port}")
    page = fetch_https_page(args.host, args.path, args.tunnel_host, args.tunnel_port, args.auth_key)
    print("----- HTTPS RESPONSE BEGIN -----")
    print(page)
    print("----- HTTPS RESPONSE END -----")