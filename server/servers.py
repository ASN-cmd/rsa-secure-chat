from Crypto.PublicKey import RSA as CryptoRSA
import socket
import threading
import json
import rsa
import time
import asyncio
import websockets
from datetime import datetime

# Global reference to server instance for WebSocket handler
server_instance = None

async def websocket_handler(websocket, path=None):
    """Global WebSocket handler function"""
    if server_instance:
        await server_instance.handle_websocket_client(websocket, path or "/")


class ChatServer:
    def __init__(self, host="0.0.0.0", port=9999, websocket_port=8765):
        global server_instance
        server_instance = self  # Set global reference
        
        self.host = host
        self.port = port
        self.websocket_port = websocket_port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Store connected clients: {username: {socket/websocket, public_key, last_seen, connection_type}}
        self.clients = {}
        self.client_lock = threading.Lock()
        
        # Store user accounts: {username: {password_hash, friends_list, public_key}}
        self.users = {}
        self.users_lock = threading.Lock()
        
        print(f"Chat server starting on {host}:{port}")
        print(f"WebSocket server will start on {host}:{websocket_port}")
    
    def start(self):
        # Start traditional socket server in a thread
        socket_thread = threading.Thread(target=self.start_socket_server)
        socket_thread.daemon = True
        socket_thread.start()
        
        # Start WebSocket server in the main thread
        try:
            asyncio.run(self.start_websocket_server())
        except KeyboardInterrupt:
            print("Server shutting down...")
    
    def start_socket_server(self):
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        print("Socket server is listening for connections...")
        
        while True:
            try:
                client_socket, address = self.server.accept()
                print(f"New socket connection from {address}")
                
                client_thread = threading.Thread(
                    target=self.handle_socket_client, 
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except Exception as e:
                print(f"Error accepting socket connection: {e}")
    
    async def start_websocket_server(self):
        print("WebSocket server is listening for connections...")
        
        # Use the global handler function
        server = await websockets.serve(
            websocket_handler,
            self.host,
            self.websocket_port
        )
        
        print("WebSocket server started successfully")
        await server.wait_closed()
    
    async def handle_websocket_client(self, websocket, path):
        username = None
        address = websocket.remote_address
        print(f"New WebSocket connection from {address} (path: {path})")
        
        try:
            async for message in websocket:
                try:
                    data = json.loads(message)
                    print(f"WebSocket received: {data}")
                    
                    response = await self.process_websocket_message(data, websocket, username)
                    
                    if response.get('action') == 'login_success':
                        username = data['username']
                    print("Sending to client:", response)
                    await websocket.send(json.dumps(response))
                    
                except json.JSONDecodeError as e:
                    print(f"WebSocket JSON decode error: {e}")
                    error_response = {"status": "error", "message": "Invalid message format"}
                    await websocket.send(json.dumps(error_response))
                except Exception as e:
                    print(f"Error processing WebSocket message: {e}")
                    error_response = {"status": "error", "message": f"Server error: {str(e)}"}
                    await websocket.send(json.dumps(error_response))
                    
        except websockets.exceptions.ConnectionClosed:
            print(f"WebSocket client {address} disconnected")
        except Exception as e:
            print(f"Error handling WebSocket client {address}: {e}")
        finally:
            if username:
                self.disconnect_user(username)
    
    def handle_socket_client(self, client_socket, address):
        username = None
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                try:
                    message = json.loads(data.decode())
                    response = self.process_message(message, client_socket, username)
                    
                    if response.get('action') == 'login_success':
                        username = message['username']
                    
                    response_data = json.dumps(response).encode()
                    client_socket.send(response_data)
                    
                except json.JSONDecodeError as e:
                    print(f"Socket JSON decode error: {e}")
                    error_response = {"status": "error", "message": "Invalid message format"}
                    client_socket.send(json.dumps(error_response).encode())
                except Exception as e:
                    print(f"Error processing socket message: {e}")
                    error_response = {"status": "error", "message": f"Server error: {str(e)}"}
                    client_socket.send(json.dumps(error_response).encode())
                    
        except Exception as e:
            print(f"Error handling socket client {address}: {e}")
        finally:
            if username:
                self.disconnect_user(username)
            client_socket.close()
    
    async def process_websocket_message(self, message, websocket, current_username):
        action = message.get('action')
        
        if action == 'register':
            return self.register_user(
                message['username'],
                message['password'],
                message.get('public_key')
            )

        
        elif action == 'login':
            return await self.login_websocket_user(message['username'], message['password'], 
                                                 message['public_key'], websocket)
        
        elif action == 'add_friend':
            return self.add_friend(current_username, message['friend_username'])
        
        elif action == 'get_friends':
            return self.get_friends(current_username)
        
        elif action == 'get_public_key':
            return self.get_user_public_key(message['username'])
        
        elif action == 'send_message':
            return await self.send_websocket_message(current_username, message['to_user'], 
                                                   message['encrypted_message'])
        
        elif action == 'get_messages':
            return self.get_pending_messages(current_username)
        
        else:
            return {"status": "error", "message": "Unknown action"}
    
    def process_message(self, message, client_socket, current_username):
        action = message.get('action')
        
        if action == 'register':
            return self.register_user(message['username'], message['password'])
        
        elif action == 'login':
            return self.login_user(message['username'], message['password'], 
                                 message['public_key'], client_socket)
        
        elif action == 'add_friend':
            return self.add_friend(current_username, message['friend_username'])
        
        elif action == 'get_friends':
            return self.get_friends(current_username)
        
        elif action == 'get_public_key':
            return self.get_user_public_key(message['username'])
        
        elif action == 'send_message':
            return self.send_message(current_username, message['to_user'], 
                                   message['encrypted_message'])
        
        elif action == 'get_messages':
            return self.get_pending_messages(current_username)
        
        else:
            return {"status": "error", "message": "Unknown action"}
    
    def register_user(self, username, password, public_key_pem=None):
        with self.users_lock:
            if username in self.users:
                return {"status": "error", "message": "Username already exists"}
        
        password_hash = hash(password)
        self.users[username] = {
            "password_hash": password_hash,
            "friends": [],
            "messages": [],
            "public_key": public_key_pem if public_key_pem else None
        }
        
        return {"status": "success", "message": "User registered successfully"}

    
    def login_user(self, username, password, public_key_pem, client_socket):
        with self.users_lock:
            if username not in self.users:
                return {"status": "error", "message": "User not found"}
            
            if hash(password) != self.users[username]["password_hash"]:
                return {"status": "error", "message": "Invalid password"}
        
        try:
            # First, try loading as PKCS#1 (python-rsa format)
            try:
                public_key = rsa.PublicKey.load_pkcs1(public_key_pem.encode())
            except ValueError:
                # If that fails, try loading as SPKI (Web Crypto API format)
                crypto_key = CryptoRSA.import_key(public_key_pem.encode())
                public_key = rsa.PublicKey(crypto_key.n, crypto_key.e)
        except Exception as e:
            return {"status": "error", "message": f"Invalid public key: {str(e)}"}

        
        with self.client_lock:
            self.clients[username] = {
                "socket": client_socket,
                "public_key": public_key,
                "last_seen": datetime.now(),
                "connection_type": "socket"
            }
        
        with self.users_lock:
            self.users[username]["public_key"] = public_key_pem
        
        return {"action": "login_success", "status": "success", 
                "message": f"Welcome {username}!"}
    
    async def login_websocket_user(self, username, password, public_key_pem, websocket):
        with self.users_lock:
            if username not in self.users:
                return {"status": "error", "message": "User not found"}
            
            if hash(password) != self.users[username]["password_hash"]:
                return {"status": "error", "message": "Invalid password"}
        
        try:
            # First, try loading as PKCS#1 (python-rsa format)
            try:
                public_key = rsa.PublicKey.load_pkcs1(public_key_pem.encode())
            except ValueError:
                # If that fails, try loading as SPKI (Web Crypto API format)
                crypto_key = CryptoRSA.import_key(public_key_pem.encode())
                public_key = rsa.PublicKey(crypto_key.n, crypto_key.e)
        except Exception as e:
            return {"status": "error", "message": f"Invalid public key: {str(e)}"}

        
        with self.client_lock:
            self.clients[username] = {
                "websocket": websocket,
                "public_key": public_key,
                "last_seen": datetime.now(),
                "connection_type": "websocket"
            }
        
        with self.users_lock:
            self.users[username]["public_key"] = public_key_pem
        
        return {"action": "login_success", "status": "success", 
                "message": f"Welcome {username}!"}
    
    def add_friend(self, username, friend_username):
        with self.users_lock:
            if friend_username not in self.users:
                return {"status": "error", "message": "User not found"}
            
            if friend_username in self.users[username]["friends"]:
                return {"status": "error", "message": "User is already your friend"}
            
            self.users[username]["friends"].append(friend_username)
            return {"status": "success", "message": f"Added {friend_username} as friend"}
    
    def get_friends(self, username):
        with self.users_lock:
            friends = self.users[username]["friends"]
        
        online_friends = []
        with self.client_lock:
            for friend in friends:
                status = "online" if friend in self.clients else "offline"
                online_friends.append({"username": friend, "status": status})
        
        return {"status": "success", "friends": online_friends}
    
    def get_user_public_key(self, username):
        with self.users_lock:
         if username not in self.users:
            return {"status": "error", "message": "User not found"}
        public_key = self.users[username]["public_key"]
        if not public_key:
            return {"status": "error", "message": "User has no public key"}
        return {
            "status": "success",
            "username": username, 
            "public_key": public_key
        }
    
    def send_message(self, from_user, to_user, encrypted_message):
        with self.users_lock:
            if to_user not in self.users:
                return {"status": "error", "message": "User not found"}
            
            if to_user not in self.users[from_user]["friends"]:
                return {"status": "error", "message": "You can only message friends"}
        
        message_data = {
            "from": from_user,
            "message": encrypted_message,
            "timestamp": datetime.now().isoformat()
        }
        
        # Try to deliver immediately if user is online
        with self.client_lock:
            if to_user in self.clients:
                try:
                    notification = {
                        "action": "new_message",
                        "from": from_user,
                        "encrypted_message": encrypted_message,
                        "timestamp": message_data["timestamp"]
                    }
                    
                    client_info = self.clients[to_user]
                    if client_info["connection_type"] == "socket":
                        client_info["socket"].send(json.dumps(notification).encode())
                    else:  # websocket
                        # Schedule the send for the websocket
                        asyncio.create_task(client_info["websocket"].send(json.dumps(notification)))
                    
                    return {"status": "success", "message": "Message delivered"}
                except Exception as e:
                    print(f"Failed to deliver message immediately: {e}")
        
        # Store message for later delivery
        with self.users_lock:
            self.users[to_user]["messages"].append(message_data)
        
        return {"status": "success", "message": "Message stored for delivery"}
    
    async def send_websocket_message(self, from_user, to_user, encrypted_message):
        with self.users_lock:
            if to_user not in self.users:
                return {"status": "error", "message": "User not found"}
            
            if to_user not in self.users[from_user]["friends"]:
                return {"status": "error", "message": "You can only message friends"}
        
        message_data = {
            "from": from_user,
            "message": encrypted_message,
            "timestamp": datetime.now().isoformat()
        }
        
        # Try to deliver immediately if user is online
        with self.client_lock:
            if to_user in self.clients:
                try:
                    notification = {
                        "action": "new_message",
                        "from": from_user,
                        "encrypted_message": encrypted_message,
                        "timestamp": message_data["timestamp"]
                    }
                    
                    client_info = self.clients[to_user]
                    if client_info["connection_type"] == "socket":
                        client_info["socket"].send(json.dumps(notification).encode())
                    else:  # websocket
                        await client_info["websocket"].send(json.dumps(notification))
                    
                    return {"status": "success", "message": "Message delivered"}
                except Exception as e:
                    print(f"Failed to deliver message immediately: {e}")
        
        # Store message for later delivery
        with self.users_lock:
            self.users[to_user]["messages"].append(message_data)
        
        return {"status": "success", "message": "Message stored for delivery"}
    
    def get_pending_messages(self, username):
        with self.users_lock:
            messages = self.users[username]["messages"].copy()
            self.users[username]["messages"] = []
        
        return {"status": "success", "messages": messages}
    
    def disconnect_user(self, username):
        with self.client_lock:
            if username in self.clients:
                del self.clients[username]
        print(f"User {username} disconnected")


if __name__ == "__main__":
    server = ChatServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    except Exception as e:
        print(f"Server error: {e}")