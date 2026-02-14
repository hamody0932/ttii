import asyncio
import websockets
import json
import base64
from datetime import datetime, timedelta

# Configuration
HOST = "0.0.0.0"
PORT = 8765
XOR_KEY = "JiM21rNU12eERlNmpqa3FuQks"

def xor_crypt(data_str, key):
    """Encrypts or Decrypts data using XOR key (Symmetric)."""
    # If encrypting, input is str, need bytes. If decrypting, input is base64 str.
    # To simplify: We will handle the base64 layer outside this function or check input type.
    
    # This function assumes input is the RAW BYTES to be XORed.
    # Returns bytes.
    pass 

def xor_cipher(data_bytes, key_str):
    key_bytes = key_str.encode('utf-8')
    result = bytearray()
    for i in range(len(data_bytes)):
        result.append(data_bytes[i] ^ key_bytes[i % len(key_bytes)])
    return result

def decrypt_payload(b64_data, key):
    try:
        data_bytes = base64.b64decode(b64_data)
        decrypted_bytes = xor_cipher(data_bytes, key)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        print(f"Decryption Error: {e}")
        return None

def encrypt_payload(json_str, key):
    data_bytes = json_str.encode('utf-8')
    encrypted_bytes = xor_cipher(data_bytes, key)
    return base64.b64encode(encrypted_bytes).decode('utf-8')

async def handler(websocket):
    print(f"New connection from {websocket.remote_address}")
    try:
        async for message in websocket:
            print(f"\nReceived: {message}")
            
            try:
                msg_json = json.loads(message)
            except json.JSONDecodeError:
                print("Invalid JSON received")
                continue

            # 1. Handle Registration
            if msg_json.get("register") is True:
                response = {
                    "success": True,
                    "message": "IP registered",
                    "ttl": 10
                }
                await websocket.send(json.dumps(response))
                print(f"Sent Register Response: {response}")

            # 2. Handle Data (License Check)
            elif "data" in msg_json:
                encrypted_req = msg_json["data"]
                decrypted_req = decrypt_payload(encrypted_req, XOR_KEY)
                
                if decrypted_req:
                    print(f"Decrypted Request: {decrypted_req}")
                    
                    # Prepare Success Response
                    # Dynamic dates: Expiry 1 year from now
                    now = datetime.now()
                    expiry = now + timedelta(days=365)
                    
                    success_payload = {
                        "status": "success",
                        "message": "License verified successfully.",
                        "data": {
                            "license_key": "Glass_Engine",
                            "expiry_date": expiry.strftime("%Y-%m-%d %H:%M:%S"),
                            "is_paid": True,
                            "hwid_lock": True,
                            "max_devices": 10000,
                            "active_devices": 5912,
                            "duration_type": "1day",
                            "version": "1.0",
                            "first_login_date": now.strftime("%Y-%m-%d %H:%M:%S"),
                            "game_type": "8ball",
                            "auth_token": "WVR4QR4CWElfcktQZVx9VlFbcU4TFQoXOSh2XA0NACM="
                        }
                    }
                    
                    success_json_str = json.dumps(success_payload)
                    encrypted_res = encrypt_payload(success_json_str, XOR_KEY)
                    
                    final_response = {
                        "data": encrypted_res
                    }
                    
                    await websocket.send(json.dumps(final_response))
                    print("Sent Processed & Encrypted Response")
                else:
                     print("Failed to decrypt request data")

    except websockets.ConnectionClosed:
        print("Connection closed")

async def main():
    print(f"Starting WebSocket Server on ws://{HOST}:{PORT}")
    print(f"XOR Key: {XOR_KEY}")
    async with websockets.serve(handler, HOST, PORT):
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Server stopped.")
