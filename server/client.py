import socket
import threading
import json
import rsa
import base64
import getpass
import queue
from datetime import datetime

class ChatClient:
    def __init__(self):
        self.socket = None
        self.public_key = None
        self.private_key = None
        self.username = None
        self.friends_public_keys = {}  # Store friends' public keys
        self.connected = False
        self.message_thread_started = False
        
        # Message queue system to handle incoming messages
        self.pending_responses = queue.Queue()
        self.waiting_for_response = False
        
        # Generate RSA keys
        print("Generating RSA keys...")
        self.public_key, self.private_key = rsa.newkeys(1024)
        print("Keys generated!")
    
    def connect_to_server(self, host="localhost", port=9999):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            self.connected = True
            print(f"Connected to {host}:{port}")
            
            # Start receiving messages thread immediately after connection
            if not self.message_thread_started:
                receive_thread = threading.Thread(target=self.receive_messages)
                receive_thread.daemon = True
                receive_thread.start()
                self.message_thread_started = True
            
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def send_request(self, request):
        try:
            print(f"Sending request: {request}")  # Debug print
            request_data = json.dumps(request).encode()
            self.socket.send(request_data)
            
            print("Waiting for response...")  # Debug print
            
            # Wait for response from the message handling thread
            self.waiting_for_response = True
            try:
                response = self.pending_responses.get(timeout=10)  # 10 second timeout
                print(f"Parsed response: {response}")  # Debug print
                return response
            except queue.Empty:
                print("Timeout waiting for response")
                return {"status": "error", "message": "Request timeout"}
            finally:
                self.waiting_for_response = False
                
        except Exception as e:
            print(f"Communication error: {e}")
            import traceback
            traceback.print_exc()
            return {"status": "error", "message": "Communication failed"}
    
    def register(self):
        print("\n=== REGISTER ===")
        username = input("Choose username: ")
        password = getpass.getpass("Choose password: ")
        
        request = {
            "action": "register",
            "username": username,
            "password": password
        }
        
        response = self.send_request(request)
        print(response["message"])
        return response["status"] == "success"
    
    def login(self):
        print("\n=== LOGIN ===")
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        
        public_key_pem = self.public_key.save_pkcs1("PEM").decode()
        
        request = {
            "action": "login",
            "username": username,
            "password": password,
            "public_key": public_key_pem
        }
        
        response = self.send_request(request)
        print(response["message"])
        
        if response["status"] == "success":
            self.username = username
            # Message thread is already running from connection time
            return True
        return False
    
    def add_friend(self):
        friend_username = input("Enter friend's username: ")
        
        request = {
            "action": "add_friend",
            "friend_username": friend_username
        }
        
        response = self.send_request(request)
        print(response["message"])
    
    def view_friends(self):
        request = {"action": "get_friends"}
        response = self.send_request(request)
        
        if response["status"] == "success":
            print("\n=== YOUR FRIENDS ===")
            if not response["friends"]:
                print("No friends added yet.")
            else:
                for friend in response["friends"]:
                    status_icon = "🟢" if friend["status"] == "online" else "🔴"
                    print(f"{status_icon} {friend['username']} ({friend['status']})")
        else:
            print(response["message"])
    
    def get_friend_public_key(self, friend_username):
        # Request friend's public key from server
        request = {
            "action": "get_public_key",
            "username": friend_username
        }
        
        response = self.send_request(request)
        if response["status"] == "success":
            try:
                public_key = rsa.PublicKey.load_pkcs1(response["public_key"].encode())
                self.friends_public_keys[friend_username] = public_key
                return public_key
            except Exception as e:
                print(f"Error loading public key: {e}")
                return None
        else:
            print(f"Could not get public key for {friend_username}: {response['message']}")
            return None
    
    def send_message(self):
        friend_username = input("Send message to: ")
        message = input("Message: ")
        
        try:
            # Get friend's public key from server
            friend_public_key = self.get_friend_public_key(friend_username)
            if not friend_public_key:
                print("Cannot send message - failed to get friend's public key")
                return
            
            # Encrypt message with friend's public key
            encrypted_message = rsa.encrypt(message.encode(), friend_public_key)
            encrypted_message_b64 = base64.b64encode(encrypted_message).decode()
            
            request = {
                "action": "send_message",
                "to_user": friend_username,
                "encrypted_message": encrypted_message_b64
            }
            
            response = self.send_request(request)
            if response["status"] == "success":
                print(f"✓ Message sent to {friend_username}")
            else:
                print(f"✗ Failed to send: {response['message']}")
                
        except Exception as e:
            print(f"Encryption error: {e}")
            import traceback
            traceback.print_exc()
    
    def check_messages(self):
        request = {"action": "get_messages"}
        response = self.send_request(request)
        
        if response["status"] == "success" and response["messages"]:
            print(f"\n=== NEW MESSAGES ({len(response['messages'])}) ===")
            for msg in response["messages"]:
                try:
                    # Decrypt message
                    encrypted_data = base64.b64decode(msg["message"])
                    decrypted_message = rsa.decrypt(encrypted_data, self.private_key).decode()
                    
                    timestamp = datetime.fromisoformat(msg["timestamp"]).strftime("%H:%M")
                    print(f"[{timestamp}] {msg['from']}: {decrypted_message}")
                    
                except Exception as e:
                    print(f"[{msg['timestamp']}] {msg['from']}: [Could not decrypt message]")
        elif response["messages"]:
            print("No new messages.")
    
    def receive_messages(self):
        """Background thread to receive all messages and route them appropriately"""
        while self.connected:
            try:
                data = self.socket.recv(4096)
                if not data:
                    break
                
                print(f"Received raw data: {data}")  # Debug print
                
                try:
                    message = json.loads(data.decode())
                    print(f"Parsed incoming message: {message}")  # Debug print
                    
                    # Check if this is a server notification (like new_message)
                    if message.get("action") == "new_message":
                        try:
                            # Decrypt the message
                            encrypted_data = base64.b64decode(message["encrypted_message"])
                            decrypted_message = rsa.decrypt(encrypted_data, self.private_key).decode()
                            
                            timestamp = datetime.fromisoformat(message["timestamp"]).strftime("%H:%M")
                            print(f"\n💬 [{timestamp}] {message['from']}: {decrypted_message}")
                            print("Command: ", end="", flush=True)  # Restore prompt
                            
                        except Exception as e:
                            print(f"\n💬 New message from {message['from']} (could not decrypt)")
                            print("Command: ", end="", flush=True)
                    
                    # If main thread is waiting for a response, this might be it
                    elif self.waiting_for_response:
                        print(f"Routing response to main thread: {message}")
                        self.pending_responses.put(message)
                    
                    # Otherwise, it might be an unsolicited server message
                    else:
                        print(f"Received unsolicited message: {message}")
                    
                except json.JSONDecodeError as e:
                    print(f"JSON decode error: {e}")
                    # If we're waiting for a response, send an error
                    if self.waiting_for_response:
                        self.pending_responses.put({"status": "error", "message": "Invalid response format"})
                    
            except Exception as e:
                if self.connected:
                    print(f"Error receiving messages: {e}")
                    # If we're waiting for a response, send an error
                    if self.waiting_for_response:
                        self.pending_responses.put({"status": "error", "message": f"Connection error: {e}"})
                break
    
    def main_menu(self):
        while True:
            print(f"\n=== CHAT APP - Logged in as {self.username} ===")
            print("1. Add friend")
            print("2. View friends")
            print("3. Send message")
            print("4. Check messages")
            print("5. Logout")
            
            choice = input("Command: ").strip()
            
            if choice == "1":
                self.add_friend()
            elif choice == "2":
                self.view_friends()
            elif choice == "3":
                self.send_message()
            elif choice == "4":
                self.check_messages()
            elif choice == "5":
                print("Logging out...")
                break
            else:
                print("Invalid choice!")
    
    def run(self):
        print("=== RSA ENCRYPTED CHAT CLIENT ===")
        
        # Get server details
        host = input("Server IP (press Enter for localhost): ").strip()
        if not host:
            host = "localhost"
        
        port = input("Port (press Enter for 9999): ").strip()
        if not port:
            port = 9999
        else:
            port = int(port)
        
        # Connect to server
        if not self.connect_to_server(host, port):
            return
        
        print("Connected to server!")
        
        # Authentication loop
        while True:
            print("\n1. Register")
            print("2. Login")
            print("3. Exit")
            
            choice = input("Choose option: ").strip()
            
            if choice == "1":
                self.register()
            elif choice == "2":
                if self.login():
                    self.main_menu()
                    break
            elif choice == "3":
                break
            else:
                print("Invalid choice!")
        
        if self.socket:
            self.connected = False
            self.socket.close()

if __name__ == "__main__":
    client = ChatClient()
    try:
        client.run()
    except KeyboardInterrupt:
        print("\nGoodbye!")
    except Exception as e:
        print(f"Client error: {e}")