"""
XProject 8BP License Server
Mimics quantum.myvippanel.shop/xpjct endpoint
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import base64
from datetime import datetime, timedelta

# XOR encryption key (25 bytes)
XOR_KEY = b'JiM21rNU12eERlNmpqa3FuQks'

def xor_crypt(data: bytes) -> bytes:
    """XOR encrypt/decrypt data with the repeating key."""
    key_len = len(XOR_KEY)
    return bytes([data[i] ^ XOR_KEY[i % key_len] for i in range(len(data))])

def encrypt(plaintext: str) -> str:
    """Encrypt plaintext string -> Base64 encoded XOR encrypted string."""
    encrypted = xor_crypt(plaintext.encode('ascii'))
    return base64.b64encode(encrypted).decode('ascii')

def decrypt(encoded: str) -> str:
    """Decrypt Base64 encoded XOR encrypted string -> plaintext string."""
    encrypted = base64.b64decode(encoded)
    return xor_crypt(encrypted).decode('ascii')


class LicenseHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        if self.path == '/xpjct':
            self.handle_license()
        else:
            self.send_error(404)

    def handle_license(self):
        # Read request body
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        try:
            # Parse JSON wrapper
            wrapper = json.loads(body)
            encrypted_data = wrapper.get('data', '')

            # Decrypt request
            decrypted_json = decrypt(encrypted_data)
            request_data = json.loads(decrypted_json)

            print(f"\n{'='*50}")
            print(f"[REQUEST] Decrypted:")
            print(json.dumps(request_data, indent=2))

            # Build response
            game_type = request_data.get('game_type', '8ball')
            hwid = request_data.get('hwid', '')
            license_key = request_data.get('license_key', '')
            version = request_data.get('version', '1.0')

            now = datetime.now()
            expiry = now + timedelta(days=365)  # 1 year license

            response_data = {
                "status": "success",
                "message": "License verified successfully.",
                "data": {
                    "license_key": license_key,
                    "expiry_date": expiry.strftime("%Y-%m-%d %H:%M:%S"),
                    "is_paid": True,
                    "hwid_lock": True,
                    "max_devices": 50000,
                    "active_devices": 1,
                    "duration_type": "lifetime",
                    "version": version,
                    "first_login_date": now.strftime("%Y-%m-%d %H:%M:%S"),
                    "game_type": game_type,
                    "auth_token": encrypt(f"{hwid}:{license_key}:{game_type}")
                }
            }

            print(f"\n[RESPONSE] Sending:")
            print(json.dumps(response_data, indent=2))
            print(f"{'='*50}\n")

            # Encrypt response
            response_json = json.dumps(response_data, separators=(',', ':'))
            encrypted_response = encrypt(response_json)

            # Send response
            response_body = json.dumps({"data": encrypted_response})
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response_body)))
            self.send_header('Cache-Control', 'public, max-age=0')
            self.end_headers()
            self.wfile.write(response_body.encode())

        except Exception as e:
            print(f"[ERROR] {e}")
            import traceback
            traceback.print_exc()
            self.send_error(500, str(e))

    def do_GET(self):
        """Health check endpoint."""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<h1>XProject License Server Running</h1>')

    def log_message(self, format, *args):
        """Custom log format."""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {args[0]}")


def main():
    HOST = '0.0.0.0'
    PORT = 8080

    server = HTTPServer((HOST, PORT), LicenseHandler)
    print(f"""
{'='*50}
  XProject 8BP License Server
{'='*50}
  Server:  http://{HOST}:{PORT}
  Endpoint: POST /xpjct
  XOR Key: {XOR_KEY.decode()}
{'='*50}
  Waiting for connections...
""")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
        server.server_close()


if __name__ == '__main__':
    main()
