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
            print(f"Sending request: {request}")
            request_data = json.dumps(request).encode()
            self.socket.send(request_data)
            
            print("Waiting for response...")
            
            # Wait for response from the message handling thread
            self.waiting_for_response = True
            try:
                response = self.pending_responses.get(timeout=10)  # 10 second timeout
                print(f"Parsed response: {response}")
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
        
        public_key_pem = self.public_key.save_pkcs1("PEM").decode()
        
        request = {
            "action": "register",
            "username": username,
            "password": password,
            "public_key": public_key_pem
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
            # Check for any pending messages after login
            print("Checking for pending messages...")
            self.check_messages()
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
        # Check if we already have the key cached
        if friend_username in self.friends_public_keys:
            return self.friends_public_keys[friend_username]
        
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
        elif response["status"] == "success":
            print("No new messages.")
        else:
            print(f"Error checking messages: {response['message']}")
    
    def view_chat_history(self):
        """Interactive chat history viewer"""
        print("\n=== CHAT HISTORY ===")
        friend_username = input("View chat with (username): ")
        
        # For now, this just shows recent messages
        # In a full implementation, you might want to store local message history
        # or request chat history from the server
        print(f"Recent messages with {friend_username}:")
        print("(Note: Only messages received while client was running are shown)")
        print("For full chat history, check the server database.")
    
    def receive_messages(self):
        """Background thread to receive all messages and route them appropriately"""
        while self.connected:
            try:
                data = self.socket.recv(4096)
                if not data:
                    break
                
                print(f"Received raw data: {data}")
                
                try:
                    message = json.loads(data.decode())
                    print(f"Parsed incoming message: {message}")
                    
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
    
    def show_help(self):
        """Display help information"""
        print("\n=== HELP ===")
        print("Available commands:")
        print("1. Add friend - Add a new friend to your contact list")
        print("2. View friends - See your friends and their online status")
        print("3. Send message - Send an encrypted message to a friend")
        print("4. Check messages - Check for new messages")
        print("5. Chat history - View chat history with a friend")
        print("6. Help - Show this help message")
        print("7. Logout - Disconnect and exit")
        print("\nNotes:")
        print("- All messages are encrypted end-to-end with RSA")
        print("- You can only message users who are your friends")
        print("- Messages are stored on the server if the recipient is offline")
        print("- Your account and friends list persist across sessions")
    
    def main_menu(self):
        while True:
            print(f"\n=== SECURE CHAT - Logged in as {self.username} ===")
            print("1. Add friend")
            print("2. View friends")
            print("3. Send message")
            print("4. Check messages")
            print("5. Chat history")
            print("6. Help")
            print("7. Logout")
            
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
                self.view_chat_history()
            elif choice == "6":
                self.show_help()
            elif choice == "7":
                print("Logging out...")
                break
            else:
                print("Invalid choice! Type '6' for help.")
    
    def run(self):
        print("=== RSA ENCRYPTED CHAT CLIENT (STATEFUL) ===")
        print("This client connects to a stateful server that preserves")
        print("your account, friends, and message history.")
        
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
            print("\n1. Register new account")
            print("2. Login to existing account")
            print("3. Exit")
            
            choice = input("Choose option: ").strip()
            
            if choice == "1":
                if self.register():
                    print("Registration successful! Please login.")
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
        import traceback
        traceback.print_exc()