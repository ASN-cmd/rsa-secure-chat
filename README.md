# 🔒 RSA Secure Chat App

A real-time chat application with **end-to-end encryption** using **RSA** in the browser.  
Built with **React**, **WebSockets**, and **Python** to ensure messages remain private between sender and receiver.

<img width="1918" height="967" alt="image" src="https://github.com/user-attachments/assets/fc9bd3d8-90a2-4c65-ae49-d7fdd520cb3f" />
<img width="1918" height="958" alt="image" src="https://github.com/user-attachments/assets/7affd34a-e382-4b2c-a777-b3bd95382b84" />
<img width="1671" height="923" alt="wireshark_ss1" src="https://github.com/user-attachments/assets/46993a47-7617-41ae-925b-bbb26d6c941f" />
<img width="176" height="233" alt="wireshark_ss2" src="https://github.com/user-attachments/assets/5fff937b-35d3-4f6f-90a4-c9f0822d3c2b" />

---

## ✨ Features

- **End-to-End Encryption** using RSA-OAEP (2048-bit)
- **Secure Public Key Exchange** via WebSocket server
- **Real-time Messaging**
- **Friend List & Chat Selection**
- **Persistent Private Key** in the browser (localStorage)
- **Simple Login & Registration**
- **Responsive UI** built with Tailwind CSS

---

## 🛠️ Tech Stack

**Frontend:**
- React (Hooks, Functional Components)
- Tailwind CSS
- Web Crypto API

**Backend:**
- Python (asyncio, websockets)
- WebSocket Server for message routing

**Security:**
- RSA-OAEP encryption
- Per-user key pairs
- Secure key import/export in the browser

---

## 📂 Project Structure

├── client

│ ├── src/

│ │ ├── App.js # Main chat UI with encryption/decryption

│ │ ├── index.js

│ │ ├── index.css

│ │ └── ...

│ └── package.json

│

├── server/

│ ├── server.py # Python WebSocket server

│ ├── client.py # Python client

│ └── ...

│

└── README.md


## ⚡ Installation & Setup
### 1️⃣ Clone the repository

git clone https://github.com/your-username/rsa-secure-chat.git

cd rsa-secure-chat


2️⃣ Backend Setup (Python WebSocket Server)

cd server

pip install websockets

python server.py


3️⃣ Frontend Setup (React)

cd client

npm install

npm start


## 🔐 How Encryption Works

1. **On Login/Register**
    - Client generates an RSA key pair in the browser.
    - Public key is sent to the server for other users to fetch.
    - Private key is stored securely in `localStorage`.

2. **Sending a Message**
    - Sender fetches recipient’s public key.
    - Message is encrypted using recipient’s public key (RSA-OAEP).
    - Encrypted Base64 message is sent via WebSocket.

3. **Receiving a Message**
    - Client decrypts Base64 message using its private key.
    - Plaintext message is displayed in the chat window.


📜 License
This project is licensed under the MIT License.

👨‍💻 Author
Aryan Nair
📧 nairaryan135@gmail.com
