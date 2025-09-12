import argparse
import sqlite3
import json
import hashlib
import os
from datetime import datetime
from Crypto.PublicKey import RSA as CryptoRSA
import socket
import threading
import rsa
import asyncio
import websockets
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import traceback

# Global reference to server instance for WebSocket handler
server_instance = None

async def websocket_handler(websocket, path=None):
    """Robust WebSocket handler with error handling"""
    print(f"New connection from {websocket.remote_address}")
    if server_instance:
        try:
            await server_instance.handle_websocket_client(websocket, path)
        except websockets.exceptions.ConnectionClosed as e:
            print(f"Client disconnected: {e.code} {e.reason}")
        except Exception as e:
            print(f"WebSocket error: {str(e)}")
            traceback.print_exc()
            try:
                await websocket.close(code=1011, reason=str(e))
            except:
                pass

class DatabaseManager:
    def __init__(self, db_path="chat_server.db"):
        self.db_path = db_path
        self.init_database()
    
    def get_connection(self):
        """Get a database connection with proper settings"""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_database(self):
        """Initialize database tables"""
        conn = self.get_connection()
        try:
            # Users table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    public_key TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            """)
            
            # Friendships table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS friendships (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    friend_id INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                    FOREIGN KEY (friend_id) REFERENCES users (id) ON DELETE CASCADE,
                    UNIQUE(user_id, friend_id)
                )
            """)
            
            # Messages table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_user_id INTEGER NOT NULL,
                    to_user_id INTEGER NOT NULL,
                    encrypted_message TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    delivered BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (from_user_id) REFERENCES users (id) ON DELETE CASCADE,
                    FOREIGN KEY (to_user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            """)
            
            # Create indexes for better performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_to_user ON messages (to_user_id, delivered)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_friendships_user ON friendships (user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users (username)")
            
            conn.commit()
            print("Database initialized successfully")
            
        except Exception as e:
            print(f"Error initializing database: {e}")
            conn.rollback()
        finally:
            conn.close()
    
    def create_user(self, username, password, public_key=None):
        """Create a new user account"""
        conn = self.get_connection()
        try:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            conn.execute(
                "INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)",
                (username, password_hash, public_key)
            )
            conn.commit()
            return True, "User registered successfully"
            
        except sqlite3.IntegrityError:
            return False, "Username already exists"
        except Exception as e:
            print(f"Error creating user: {e}")
            return False, f"Registration failed: {str(e)}"
        finally:
            conn.close()
    
    def authenticate_user(self, username, password):
        """Authenticate user login"""
        conn = self.get_connection()
        try:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            cursor = conn.execute(
                "SELECT id, username, public_key FROM users WHERE username = ? AND password_hash = ?",
                (username, password_hash)
            )
            user = cursor.fetchone()
            
            if user:
                # Update last login time
                conn.execute(
                    "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                    (user['id'],)
                )
                conn.commit()
                return True, dict(user)
            else:
                return False, None
                
        except Exception as e:
            print(f"Error authenticating user: {e}")
            return False, None
        finally:
            conn.close()
    
    def update_user_public_key(self, username, public_key):
        """Update user's public key"""
        conn = self.get_connection()
        try:
            conn.execute(
                "UPDATE users SET public_key = ? WHERE username = ?",
                (public_key, username)
            )
            conn.commit()
            return True
        except Exception as e:
            print(f"Error updating public key: {e}")
            return False
        finally:
            conn.close()
    
    def add_friendship(self, username, friend_username):
        """Add a friendship relationship"""
        conn = self.get_connection()
        try:
            # Get user IDs
            cursor = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            
            cursor = conn.execute("SELECT id FROM users WHERE username = ?", (friend_username,))
            friend = cursor.fetchone()
            
            if not user or not friend:
                return False, "User not found"
            
            if user['id'] == friend['id']:
                return False, "Cannot add yourself as friend"
            
            # Add friendship (one-way for now, you can make it bidirectional if needed)
            conn.execute(
                "INSERT INTO friendships (user_id, friend_id) VALUES (?, ?)",
                (user['id'], friend['id'])
            )
            conn.commit()
            return True, f"Added {friend_username} as friend"
            
        except sqlite3.IntegrityError:
            return False, "User is already your friend"
        except Exception as e:
            print(f"Error adding friendship: {e}")
            return False, f"Failed to add friend: {str(e)}"
        finally:
            conn.close()
    
    def get_user_friends(self, username):
        """Get user's friends list with online status"""
        conn = self.get_connection()
        try:
            cursor = conn.execute("""
                SELECT u2.username, u2.last_login
                FROM users u1
                JOIN friendships f ON u1.id = f.user_id
                JOIN users u2 ON f.friend_id = u2.id
                WHERE u1.username = ?
                ORDER BY u2.username
            """, (username,))
            
            friends = cursor.fetchall()
            return [dict(friend) for friend in friends]
            
        except Exception as e:
            print(f"Error getting friends: {e}")
            return []
        finally:
            conn.close()
    
    def get_user_public_key(self, username):
        """Get a user's public key"""
        conn = self.get_connection()
        try:
            cursor = conn.execute(
                "SELECT public_key FROM users WHERE username = ?",
                (username,)
            )
            result = cursor.fetchone()
            return result['public_key'] if result else None
            
        except Exception as e:
            print(f"Error getting public key: {e}")
            return None
        finally:
            conn.close()
    
    def store_message(self, from_username, to_username, encrypted_message):
        """Store an encrypted message"""
        conn = self.get_connection()
        try:
            # Get user IDs
            cursor = conn.execute("SELECT id FROM users WHERE username = ?", (from_username,))
            from_user = cursor.fetchone()
            
            cursor = conn.execute("SELECT id FROM users WHERE username = ?", (to_username,))
            to_user = cursor.fetchone()
            
            if not from_user or not to_user:
                return False, "User not found"
            
            conn.execute("""
                INSERT INTO messages (from_user_id, to_user_id, encrypted_message)
                VALUES (?, ?, ?)
            """, (from_user['id'], to_user['id'], encrypted_message))
            
            conn.commit()
            return True, "Message stored"
            
        except Exception as e:
            print(f"Error storing message: {e}")
            return False, f"Failed to store message: {str(e)}"
        finally:
            conn.close()
    
    def get_pending_messages(self, username):
        """Get pending messages for a user"""
        conn = self.get_connection()
        try:
            cursor = conn.execute("""
                SELECT m.id, u.username as from_user, m.encrypted_message, m.timestamp
                FROM messages m
                JOIN users u ON m.from_user_id = u.id
                JOIN users u2 ON m.to_user_id = u2.id
                WHERE u2.username = ? AND m.delivered = FALSE
                ORDER BY m.timestamp
            """, (username,))
            
            messages = cursor.fetchall()
            message_list = []
            message_ids = []
            
            for msg in messages:
                message_list.append({
                    'from': msg['from_user'],
                    'message': msg['encrypted_message'],
                    'timestamp': msg['timestamp']
                })
                message_ids.append(msg['id'])
            
            # Mark messages as delivered
            if message_ids:
                placeholders = ','.join('?' * len(message_ids))
                conn.execute(f"UPDATE messages SET delivered = TRUE WHERE id IN ({placeholders})", message_ids)
                conn.commit()
            
            return message_list
            
        except Exception as e:
            print(f"Error getting pending messages: {e}")
            return []
        finally:
            conn.close()
    
    def is_friend(self, username, friend_username):
        """Check if two users are friends"""
        conn = self.get_connection()
        try:
            cursor = conn.execute("""
                SELECT 1 FROM users u1
                JOIN friendships f ON u1.id = f.user_id
                JOIN users u2 ON f.friend_id = u2.id
                WHERE u1.username = ? AND u2.username = ?
            """, (username, friend_username))
            
            return cursor.fetchone() is not None
            
        except Exception as e:
            print(f"Error checking friendship: {e}")
            return False
        finally:
            conn.close()
    
    def get_user_stats(self):
        """Get database statistics"""
        conn = self.get_connection()
        try:
            cursor = conn.execute("SELECT COUNT(*) as user_count FROM users")
            user_count = cursor.fetchone()['user_count']
            
            cursor = conn.execute("SELECT COUNT(*) as message_count FROM messages")
            message_count = cursor.fetchone()['message_count']
            
            cursor = conn.execute("SELECT COUNT(*) as friendship_count FROM friendships")
            friendship_count = cursor.fetchone()['friendship_count']
            
            return {
                'users': user_count,
                'messages': message_count,
                'friendships': friendship_count
            }
        except Exception as e:
            print(f"Error getting stats: {e}")
            return {'users': 0, 'messages': 0, 'friendships': 0}
        finally:
            conn.close()

class ChatServer:
    def __init__(self, host="0.0.0.0", port=9999, websocket_port=8765, db_path=None):
        self.db_path = db_path or os.path.join(os.getcwd(), "chat_server.db")
        self.db = DatabaseManager(self.db_path)
        
        self.host = host
        self.port = port
        self.websocket_port = websocket_port
        
        # Initialize TCP socket server
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Client management
        self.clients = {}
        self.client_lock = threading.Lock()
        
        stats = self.db.get_user_stats()
        print(f"Server starting on:\n"
              f"- HTTP: {host}:{port}\n"
              f"- WebSocket: {host}:{websocket_port}\n"
              f"- Health: {host}:5000\n"
              f"Database stats: {stats['users']} users, {stats['messages']} messages")

    def start_health_check(self, port=5000):
        """Enhanced health check server"""
        class HealthHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/health':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/plain')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(b'OK')
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def log_message(self, format, *args):
                # Suppress health check logs
                return
        
        def run_server():
            try:
                server = HTTPServer(('0.0.0.0', port), HealthHandler)
                print(f"Health check server running on port {port}")
                server.serve_forever()
            except Exception as e:
                print(f"Health check server error: {e}")

        health_thread = threading.Thread(target=run_server, daemon=True)
        health_thread.start()

    def start(self):
        """Start all server components"""
        global server_instance
        server_instance = self
        
        # Start health check
        self.start_health_check()
        
        # Start TCP socket server in background thread
        socket_thread = threading.Thread(target=self.start_socket_server, daemon=True)
        socket_thread.start()
        
        # Start WebSocket server in main thread
        try:
            asyncio.run(self.start_websocket_server())
        except KeyboardInterrupt:
            print("\nServer shutting down...")
        except Exception as e:
            print(f"Server error: {e}")
            traceback.print_exc()
    
    def start_socket_server(self):
        try:
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
        except Exception as e:
            print(f"Socket server error: {e}")
            traceback.print_exc()
    
    async def start_websocket_server(self):
        print(f"Starting WebSocket server on {self.host}:{self.websocket_port}")
        
        try:
            server = await websockets.serve(
                websocket_handler,
                self.host,
                self.websocket_port,
                ping_interval=30,
                ping_timeout=10,
                max_size=2**20,  # 1MB max message
                origins=None  # Allow all origins (lock this down in production)
            )
            print("WebSocket server started successfully")
            await server.wait_closed()
        except Exception as e:
            print(f"WebSocket server error: {e}")
            traceback.print_exc()
    
    async def handle_websocket_client(self, websocket, path):
        username = None
        address = websocket.remote_address
        print(f"New WebSocket connection from {address} (path: {path})")
        
        try:
            # Send welcome message
            welcome = {"action": "welcome", "message": "Connected to RSA Chat Server"}
            await websocket.send(json.dumps(welcome))
            print(f"Sent welcome message to {address}")
            
            async for message in websocket:
                try:
                    print(f"Received raw message: {message}")
                    data = json.loads(message)
                    print(f"WebSocket received from {address}: {data}")
                    
                    response = await self.process_websocket_message(data, websocket, username)
                    
                    # Update username after successful login
                    if response.get('action') == 'login_success':
                        username = data['username']
                        print(f"User {username} logged in via WebSocket from {address}")
                        # Store the username in the client info
                        with self.client_lock:
                            if username in self.clients:
                                self.clients[username]['username'] = username
                    
                    print(f"Sending response to {address} (user: {username}):", response)
                    await websocket.send(json.dumps(response))
                    
                except json.JSONDecodeError as e:
                    print(f"WebSocket JSON decode error from {address}: {e}")
                    error_response = {"status": "error", "message": "Invalid message format"}
                    try:
                        await websocket.send(json.dumps(error_response))
                    except:
                        break
                except Exception as e:
                    print(f"Error processing WebSocket message from {address}: {e}")
                    traceback.print_exc()
                    error_response = {"status": "error", "message": f"Server error: {str(e)}"}
                    try:
                        await websocket.send(json.dumps(error_response))
                    except:
                        break
                    
        except websockets.exceptions.ConnectionClosed as e:
            print(f"WebSocket client {address} (user: {username}) disconnected normally: {e.code} {e.reason}")
        except Exception as e:
            print(f"Error handling WebSocket client {address} (user: {username}): {e}")
            traceback.print_exc()
        finally:
            if username:
                self.disconnect_user(username)
                print(f"Cleaned up user {username} from {address}")
    
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
        
        if action == 'ping':
            return {"action": "pong", "status": "success"}
        
        elif action == 'register':
            success, msg = self.db.create_user(
                message['username'],
                message['password'],
                message.get('public_key')
            )
            return {"status": "success" if success else "error", "message": msg}
        
        elif action == 'login':
            return await self.login_websocket_user(
                message['username'], 
                message['password'], 
                message['public_key'], 
                websocket
            )
        
        elif action == 'add_friend':
            if not current_username:
                return {"status": "error", "message": "Not authenticated"}
            success, msg = self.db.add_friendship(current_username, message['friend_username'])
            return {"status": "success" if success else "error", "message": msg}
        
        elif action == 'get_friends':
            if not current_username:
                return {"status": "error", "message": "Not authenticated"}
            friends = self.db.get_user_friends(current_username)
            # Add online status
            online_friends = []
            with self.client_lock:
                for friend in friends:
                    status = "online" if friend['username'] in self.clients else "offline"
                    online_friends.append({"username": friend['username'], "status": status})
            return {"status": "success", "friends": online_friends}
        
        elif action == 'get_public_key':
            public_key = self.db.get_user_public_key(message['username'])
            if public_key:
                return {
                    "status": "success",
                    "username": message['username'],
                    "public_key": public_key
                }
            else:
                return {"status": "error", "message": "User not found or no public key"}
        
        elif action == 'send_message':
            if not current_username:
                return {"status": "error", "message": "Not authenticated"}
            return await self.send_websocket_message(
                current_username, 
                message['to_user'], 
                message['encrypted_message']
            )
        
        elif action == 'get_messages':
            if not current_username:
                return {"status": "error", "message": "Not authenticated"}
            messages = self.db.get_pending_messages(current_username)
            return {"status": "success", "messages": messages}
        
        else:
            return {"status": "error", "message": f"Unknown action: {action}"}
    
    def process_message(self, message, client_socket, current_username):
        action = message.get('action')
        
        if action == 'register':
            success, msg = self.db.create_user(
                message['username'], 
                message['password'],
                message.get('public_key')
            )
            return {"status": "success" if success else "error", "message": msg}
        
        elif action == 'login':
            return self.login_user(
                message['username'], 
                message['password'], 
                message['public_key'], 
                client_socket
            )
        
        elif action == 'add_friend':
            success, msg = self.db.add_friendship(current_username, message['friend_username'])
            return {"status": "success" if success else "error", "message": msg}
        
        elif action == 'get_friends':
            friends = self.db.get_user_friends(current_username)
            # Add online status
            online_friends = []
            with self.client_lock:
                for friend in friends:
                    status = "online" if friend['username'] in self.clients else "offline"
                    online_friends.append({"username": friend['username'], "status": status})
            return {"status": "success", "friends": online_friends}
        
        elif action == 'get_public_key':
            public_key = self.db.get_user_public_key(message['username'])
            if public_key:
                return {
                    "status": "success",
                    "username": message['username'],
                    "public_key": public_key
                }
            else:
                return {"status": "error", "message": "User not found or no public key"}
        
        elif action == 'send_message':
            return self.send_message(
                current_username, 
                message['to_user'], 
                message['encrypted_message']
            )
        
        elif action == 'get_messages':
            messages = self.db.get_pending_messages(current_username)
            return {"status": "success", "messages": messages}
        
        else:
            return {"status": "error", "message": "Unknown action"}
    
    def login_user(self, username, password, public_key_pem, client_socket):
        success, user_data = self.db.authenticate_user(username, password)
        
        if not success:
            return {"status": "error", "message": "Invalid username or password"}
        
        try:
            # Parse the RSA public key
            try:
                public_key = rsa.PublicKey.load_pkcs1(public_key_pem.encode())
            except ValueError:
                crypto_key = CryptoRSA.import_key(public_key_pem.encode())
                public_key = rsa.PublicKey(crypto_key.n, crypto_key.e)
        except Exception as e:
            return {"status": "error", "message": f"Invalid public key: {str(e)}"}
        
        # Update public key in database if different
        if user_data['public_key'] != public_key_pem:
            self.db.update_user_public_key(username, public_key_pem)
        
        # Add to connected clients
        with self.client_lock:
            self.clients[username] = {
                "socket": client_socket,
                "public_key": public_key,
                "last_seen": datetime.now(),
                "connection_type": "socket"
            }
        
        return {"action": "login_success", "status": "success", 
                "message": f"Welcome back {username}!"}
    
    async def login_websocket_user(self, username, password, public_key_pem, websocket):
        print(f"Attempting login for user: {username}")
        success, user_data = self.db.authenticate_user(username, password)
        
        if not success:
            print(f"Authentication failed for user: {username}")
            return {"status": "error", "message": "Invalid username or password"}
        
        try:
            # Parse the RSA public key (only if provided)
            if public_key_pem:
                try:
                    public_key = rsa.PublicKey.load_pkcs1(public_key_pem.encode())
                except ValueError:
                    crypto_key = CryptoRSA.import_key(public_key_pem.encode())
                    public_key = rsa.PublicKey(crypto_key.n, crypto_key.e)
                
                # Update public key in database if different
                if user_data['public_key'] != public_key_pem:
                    self.db.update_user_public_key(username, public_key_pem)
            else:
                public_key = None
        except Exception as e:
            print(f"Invalid public key for user {username}: {e}")
            return {"status": "error", "message": f"Invalid public key: {str(e)}"}
        
        # Add to connected clients
        with self.client_lock:
            # Remove any existing connection for this user
            if username in self.clients:
                print(f"User {username} already connected, replacing connection")
            
            self.clients[username] = {
                "websocket": websocket,
                "public_key": public_key,
                "last_seen": datetime.now(),
                "connection_type": "websocket",
                "username": username  # Store username for easy access
            }
            print(f"User {username} added to connected clients. Total clients: {len(self.clients)}")
        
        return {"action": "login_success", "status": "success", 
                "message": f"Welcome back {username}!"}
    
    def send_message(self, from_user, to_user, encrypted_message):
        # Check if users are friends
        if not self.db.is_friend(from_user, to_user):
            return {"status": "error", "message": "You can only message friends"}
        
        # Try to deliver immediately if user is online
        with self.client_lock:
            if to_user in self.clients:
                try:
                    notification = {
                        "action": "new_message",
                        "from": from_user,
                        "encrypted_message": encrypted_message,
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    client_info = self.clients[to_user]
                    if client_info["connection_type"] == "socket":
                        client_info["socket"].send(json.dumps(notification).encode())
                    else:  # websocket
                        asyncio.create_task(client_info["websocket"].send(json.dumps(notification)))
                    
                    # Still store the message for history
                    self.db.store_message(from_user, to_user, encrypted_message)
                    return {"status": "success", "message": "Message delivered"}
                    
                except Exception as e:
                    print(f"Failed to deliver message immediately: {e}")
        
        # Store message for later delivery
        success, msg = self.db.store_message(from_user, to_user, encrypted_message)
        if success:
            return {"status": "success", "message": "Message stored for delivery"}
        else:
            return {"status": "error", "message": msg}
    
    async def send_websocket_message(self, from_user, to_user, encrypted_message):
        print(f"Attempting to send message from {from_user} to {to_user}")
        
        # Check if users are friends
        if not self.db.is_friend(from_user, to_user):
            print(f"Users {from_user} and {to_user} are not friends")
            return {"status": "error", "message": "You can only message friends"}
        
        # Store message first
        success, msg = self.db.store_message(from_user, to_user, encrypted_message)
        if not success:
            print(f"Failed to store message: {msg}")
            return {"status": "error", "message": msg}
        
        # Try to deliver immediately if user is online
        message_delivered = False
        with self.client_lock:
            print(f"Current online users: {list(self.clients.keys())}")
            if to_user in self.clients:
                try:
                    notification = {
                        "action": "new_message",
                        "from": from_user,
                        "encrypted_message": encrypted_message,
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    client_info = self.clients[to_user]
                    print(f"Delivering message to {to_user} via {client_info['connection_type']}")
                    
                    if client_info["connection_type"] == "socket":
                        client_info["socket"].send(json.dumps(notification).encode())
                        print(f"Message sent to {to_user} via socket")
                    else:  # websocket
                        await client_info["websocket"].send(json.dumps(notification))
                        print(f"Message sent to {to_user} via websocket")
                    
                    message_delivered = True
                    
                except Exception as e:
                    print(f"Failed to deliver message immediately to {to_user}: {e}")
                    traceback.print_exc()
            else:
                print(f"User {to_user} is not online")
        
        if message_delivered:
            return {"status": "success", "message": f"Message delivered to {to_user}"}
        else:
            return {"status": "success", "message": f"Message stored for {to_user} (user offline)"}
    
    def disconnect_user(self, username):
        with self.client_lock:
            if username in self.clients:
                print(f"Disconnecting user: {username}")
                del self.clients[username]
                print(f"User {username} disconnected. Remaining clients: {len(self.clients)}")
            else:
                print(f"Attempted to disconnect user {username} but not found in clients list")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='RSA Chat Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=9999, help='TCP server port')
    parser.add_argument('--ws-port', type=int, default=8765, help='WebSocket port')
    parser.add_argument('--db', default='chat_server.db', help='Database path')
    
    args = parser.parse_args()
    
    try:
        server = ChatServer(
            host=args.host,
            port=args.port,
            websocket_port=args.ws_port,
            db_path=args.db
        )
        server.start()
    except Exception as e:
        print(f"Failed to start server: {e}")
        import traceback
        traceback.print_exc()