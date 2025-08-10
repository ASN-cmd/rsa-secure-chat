import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Send, Users, UserPlus, LogOut, MessageCircle, Shield, Lock, User } from 'lucide-react';

const ChatApp = () => {
  const [connected, setConnected] = useState(false);
  const [loggedIn, setLoggedIn] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [serverUrl, setServerUrl] = useState('ws://localhost:8765');
  const [currentUser, setCurrentUser] = useState('');
  const [friends, setFriends] = useState([]);
  const [messages, setMessages] = useState({});
  const [activeChat, setActiveChat] = useState('');
  const [newMessage, setNewMessage] = useState('');
  const [newFriend, setNewFriend] = useState('');
  const [showAddFriend, setShowAddFriend] = useState(false);
  const [authMode, setAuthMode] = useState('login');
  const [notification, setNotification] = useState({ message: '', type: '' });
  const [publicKey, setPublicKey] = useState('');
  const [privateKeyPem, setPrivateKeyPem] = useState('');

  const websocket = useRef(null);
  const messagesEndRef = useRef(null);
  const friendPublicKeys = useRef({});

  // Generate RSA keys on mount
  const generateRSAKeys = useCallback(async () => {
    try {
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
      );

      const publicKeyPem = await exportKey(keyPair.publicKey, 'public');
      const privateKeyPem = await exportKey(keyPair.privateKey, 'private');

      setPublicKey(publicKeyPem);
      setPrivateKeyPem(privateKeyPem);

      showNotification('RSA keys generated successfully!', 'success');
    } catch (error) {
      console.error('Error generating keys:', error);
      showNotification('Failed to generate RSA keys', 'error');
    }
  }, []);

  useEffect(() => {
    generateRSAKeys();
  }, [generateRSAKeys]);

  const exportKey = async (key, type) => {
    const exported = await window.crypto.subtle.exportKey(
      type === 'public' ? 'spki' : 'pkcs8',
      key
    );
    const exportedAsString = arrayBufferToBase64(exported);
    const pemType = type === 'public' ? 'PUBLIC KEY' : 'PRIVATE KEY';
    return `-----BEGIN ${pemType}-----\n${exportedAsString}\n-----END ${pemType}-----`;
  };

  const arrayBufferToBase64 = (buffer) => {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  };

  const base64ToArrayBuffer = (base64) => {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  };

  const importPrivateKey = async (pem) => {
    const pemContents = pem.replace(/-----.*-----/g, '').replace(/\n/g, '');
    const binaryDer = base64ToArrayBuffer(pemContents);
    return crypto.subtle.importKey(
      'pkcs8',
      binaryDer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['decrypt']
    );
  };

  const importPublicKey = async (pem) => {
    const pemContents = pem.replace(/-----.*-----/g, '').replace(/\n/g, '');
    const binaryDer = base64ToArrayBuffer(pemContents);
    return crypto.subtle.importKey(
      'spki',
      binaryDer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['encrypt']
    );
  };

  const showNotification = (message, type) => {
    setNotification({ message, type });
    setTimeout(() => setNotification({ message: '', type: '' }), 3000);
  };

  const connectToServer = () => {
    try {
      websocket.current = new WebSocket(serverUrl);

      websocket.current.onopen = () => {
        setConnected(true);
        showNotification('Connected to server!', 'success');
      };

      websocket.current.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleServerMessage(data);
      };

      websocket.current.onclose = () => {
        setConnected(false);
        setLoggedIn(false);
        showNotification('Disconnected from server', 'error');
      };

      websocket.current.onerror = (error) => {
        console.error('WebSocket error:', error);
        showNotification('Connection error', 'error');
      };

    } catch (error) {
      showNotification('Failed to connect to server', 'error');
    }
  };

  const sendMessage = (action, data) => {
    if (websocket.current && websocket.current.readyState === WebSocket.OPEN) {
      websocket.current.send(JSON.stringify({ action, ...data }));
    }
  };

  const handleServerMessage = (data) => {
    if (data.action === 'new_message') {
      decryptAndDisplayMessage(data);
    } else if (data.action === 'login_success') {
      setLoggedIn(true);
      setCurrentUser(username);
      showNotification(data.message, 'success');
      loadFriends();
    } else if (data.status === 'success') {
      if (data.friends) setFriends(data.friends);
      if (data.public_key) friendPublicKeys.current[data.username] = data.public_key;
      if (data.message && !data.friends) showNotification(data.message, 'success');
    } else if (data.status === 'error') {
      showNotification(data.message, 'error');
    }
  };

  const decryptAndDisplayMessage = async (messageData) => {
    try {
      const privKey = await importPrivateKey(privateKeyPem);
      const encryptedBytes = Uint8Array.from(atob(messageData.encrypted_message), c => c.charCodeAt(0));
      const decryptedBuffer = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privKey, encryptedBytes);
      const decryptedText = new TextDecoder().decode(decryptedBuffer);

      const newMsg = {
        from: messageData.from,
        text: decryptedText,
        timestamp: new Date(messageData.timestamp),
        encrypted: false
      };

      setMessages(prev => ({
        ...prev,
        [messageData.from]: [...(prev[messageData.from] || []), newMsg]
      }));

      showNotification(`New message from ${messageData.from}`, 'info');
    } catch (error) {
      console.error('Error decrypting message:', error);
    }
  };

  const handleAuth = () => {
    if (!username || !password) {
      showNotification('Please enter username and password', 'error');
      return;
    }

    if (!publicKey) {
      showNotification('RSA keys not ready. Please wait...', 'error');
      return;
    }

    sendMessage(authMode, {
      username,
      password,
      public_key: publicKey
    });
  };

  const loadFriends = () => sendMessage('get_friends', {});

  const addFriend = () => {
    if (!newFriend) {
      showNotification('Please enter a username', 'error');
      return;
    }

    sendMessage('add_friend', { friend_username: newFriend });
    setNewFriend('');
    setShowAddFriend(false);
  };

  const startChat = (friendUsername) => {
    setActiveChat(friendUsername);
    if (!messages[friendUsername]) {
      setMessages(prev => ({ ...prev, [friendUsername]: [] }));
    }

    if (!friendPublicKeys.current[friendUsername]) {
      sendMessage('get_public_key', { username: friendUsername });
    }
  };

  const sendChatMessage = async () => {
    if (!newMessage.trim() || !activeChat) return;

    try {
      if (!friendPublicKeys.current[activeChat]) {
        showNotification("No public key for friend. Please wait...", "error");
        return;
      }

      const pubKey = await importPublicKey(friendPublicKeys.current[activeChat]);
      const encryptedBuffer = await crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        pubKey,
        new TextEncoder().encode(newMessage)
      );
      const encryptedBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer)));

      sendMessage('send_message', {
        to_user: activeChat,
        encrypted_message: encryptedBase64
      });

      const newMsg = {
        from: currentUser,
        text: newMessage,
        timestamp: new Date(),
        encrypted: false
      };

      setMessages(prev => ({
        ...prev,
        [activeChat]: [...(prev[activeChat] || []), newMsg]
      }));

      setNewMessage('');
    } catch (error) {
      showNotification('Failed to send message', 'error');
      console.error(error);
    }
  };

  const logout = () => {
    if (websocket.current) websocket.current.close();
    setLoggedIn(false);
    setCurrentUser('');
    setUsername('');
    setPassword('');
    setActiveChat('');
    setMessages({});
    setFriends([]);
    friendPublicKeys.current = {};
  };

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // ---------- UI RENDER ----------
  if (!connected) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-900 via-purple-900 to-indigo-900 flex items-center justify-center p-4">
        <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-8 w-full max-w-md border border-white/20">
          <div className="text-center mb-6">
            <Shield className="w-16 h-16 mx-auto mb-4 text-blue-400" />
            <h1 className="text-2xl font-bold text-white mb-2">RSA Secure Chat</h1>
            <p className="text-gray-300">End-to-end encrypted messaging</p>
          </div>
          <div className="space-y-4">
            <input
              type="text"
              placeholder="Server WebSocket URL"
              value={serverUrl}
              onChange={(e) => setServerUrl(e.target.value)}
              className="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/30 text-white placeholder-gray-400 focus:outline-none focus:border-blue-400"
            />
            <button
              onClick={connectToServer}
              className="w-full bg-gradient-to-r from-blue-500 to-purple-600 text-white py-3 rounded-lg font-semibold hover:from-blue-600 hover:to-purple-700 transition-all"
            >
              Connect to Server
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (!loggedIn) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-900 via-purple-900 to-indigo-900 flex items-center justify-center p-4">
        <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-8 w-full max-w-md border border-white/20">
          <div className="text-center mb-6">
            <Lock className="w-16 h-16 mx-auto mb-4 text-green-400" />
            <h1 className="text-2xl font-bold text-white mb-2">
              {authMode === 'login' ? 'Login' : 'Register'}
            </h1>
            <p className="text-gray-300">Secure authentication required</p>
          </div>
          <div className="space-y-4">
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/30 text-white placeholder-gray-400 focus:outline-none focus:border-blue-400"
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleAuth()}
              className="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/30 text-white placeholder-gray-400 focus:outline-none focus:border-blue-400"
            />
            <button
              onClick={handleAuth}
              className="w-full bg-gradient-to-r from-green-500 to-blue-600 text-white py-3 rounded-lg font-semibold hover:from-green-600 hover:to-blue-700 transition-all"
            >
              {authMode === 'login' ? 'Login' : 'Register'}
            </button>
            <button
              onClick={() => setAuthMode(authMode === 'login' ? 'register' : 'login')}
              className="w-full text-gray-300 hover:text-white transition-colors"
            >
              {authMode === 'login' ? 'Need an account? Register' : 'Have an account? Login'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      {notification.message && (
        <div className={`fixed top-4 right-4 z-50 p-4 rounded-lg text-white ${
          notification.type === 'success' ? 'bg-green-500' : 
          notification.type === 'error' ? 'bg-red-500' : 'bg-blue-500'
        }`}>
          {notification.message}
        </div>
      )}

      <div className="flex h-screen">
        {/* Sidebar */}
        <div className="w-80 bg-white/10 backdrop-blur-lg border-r border-white/20">
          <div className="p-4 border-b border-white/20">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 bg-gradient-to-r from-blue-500 to-purple-600 rounded-full flex items-center justify-center">
                  <User className="w-5 h-5 text-white" />
                </div>
                <div>
                  <div className="font-semibold text-white">{currentUser}</div>
                  <div className="text-sm text-green-400">Online</div>
                </div>
              </div>
              <button
                onClick={logout}
                className="p-2 text-gray-400 hover:text-white hover:bg-white/10 rounded-lg transition-colors"
              >
                <LogOut className="w-5 h-5" />
              </button>
            </div>
          </div>

          <div className="p-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold text-white flex items-center">
                <Users className="w-5 h-5 mr-2" />
                Friends ({friends.length})
              </h3>
              <button
                onClick={() => setShowAddFriend(true)}
                className="p-2 text-gray-400 hover:text-white hover:bg-white/10 rounded-lg transition-colors"
              >
                <UserPlus className="w-4 h-4" />
              </button>
            </div>

            {showAddFriend && (
              <div className="mb-4 p-3 bg-white/10 rounded-lg border border-white/20">
                <input
                  type="text"
                  placeholder="Enter username"
                  value={newFriend}
                  onChange={(e) => setNewFriend(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && addFriend()}
                  className="w-full px-3 py-2 mb-2 rounded-lg bg-white/10 border border-white/30 text-white placeholder-gray-400 focus:outline-none focus:border-blue-400"
                />
                <div className="flex space-x-2">
                  <button
                    onClick={addFriend}
                    className="flex-1 bg-blue-500 text-white py-2 rounded-lg hover:bg-blue-600 transition-colors"
                  >
                    Add
                  </button>
                  <button
                    onClick={() => {setShowAddFriend(false); setNewFriend('');}}
                    className="flex-1 bg-gray-500 text-white py-2 rounded-lg hover:bg-gray-600 transition-colors"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}

            <div className="space-y-2">
              {friends.map((friend) => (
                <div
                  key={friend.username}
                  onClick={() => startChat(friend.username)}
                  className={`p-3 rounded-lg cursor-pointer transition-all ${
                    activeChat === friend.username 
                      ? 'bg-blue-500/20 border border-blue-400' 
                      : 'hover:bg-white/10 border border-transparent'
                  }`}
                >
                  <div className="flex items-center space-x-3">
                    <div className={`w-3 h-3 rounded-full ${
                      friend.status === 'online' ? 'bg-green-400' : 'bg-gray-400'
                    }`}></div>
                    <div className="flex-1">
                      <div className="font-medium text-white">{friend.username}</div>
                      <div className={`text-sm ${
                        friend.status === 'online' ? 'text-green-400' : 'text-gray-400'
                      }`}>
                        {friend.status}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {friends.length === 0 && (
              <div className="text-center text-gray-400 py-8">
                <Users className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>No friends added yet</p>
                <p className="text-sm">Click the + button to add friends</p>
              </div>
            )}
          </div>
        </div>

        {/* Main Chat Area */}
        <div className="flex-1 flex flex-col">
          {!activeChat ? (
            <div className="flex-1 flex items-center justify-center bg-black/20">
              <div className="text-center text-gray-400">
                <MessageCircle className="w-16 h-16 mx-auto mb-4 opacity-50" />
                <h3 className="text-xl font-semibold mb-2">Select a chat to start messaging</h3>
                <p>Choose a friend from the sidebar to begin your secure conversation</p>
              </div>
            </div>
          ) : (
            <>
              <div className="p-4 bg-white/10 backdrop-blur-lg border-b border-white/20">
                <div className="flex items-center space-x-3">
                  <div className="w-10 h-10 bg-gradient-to-r from-green-500 to-blue-600 rounded-full flex items-center justify-center">
                    <User className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <div className="font-semibold text-white">{activeChat}</div>
                    <div className="text-sm text-gray-400 flex items-center">
                      <Shield className="w-3 h-3 mr-1" />
                      End-to-end encrypted
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex-1 overflow-y-auto p-4 space-y-4">
                {(messages[activeChat] || []).map((message, index) => (
                  <div
                    key={index}
                    className={`flex ${message.from === currentUser ? 'justify-end' : 'justify-start'}`}
                  >
                    <div className={`max-w-xs lg:max-w-md px-4 py-2 rounded-2xl ${
                      message.from === currentUser
                        ? 'bg-gradient-to-r from-blue-500 to-purple-600 text-white'
                        : 'bg-white/10 text-white border border-white/20'
                    }`}>
                      <div className="mb-1">
                        {message.encrypted && (
                          <div className="flex items-center text-yellow-400 text-xs mb-1">
                            <Lock className="w-3 h-3 mr-1" />
                            Encrypted
                          </div>
                        )}
                        <p className={message.encrypted ? 'italic text-gray-300' : ''}>{message.text}</p>
                      </div>
                      <div className={`text-xs ${
                        message.from === currentUser ? 'text-blue-100' : 'text-gray-400'
                      }`}>
                        {message.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </div>
                    </div>
                  </div>
                ))}
                <div ref={messagesEndRef} />
              </div>

              <div className="p-4 bg-white/10 backdrop-blur-lg border-t border-white/20">
                <div className="flex space-x-4">
                  <input
                    type="text"
                    placeholder="Type your message..."
                    value={newMessage}
                    onChange={(e) => setNewMessage(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && sendChatMessage()}
                    className="flex-1 px-4 py-3 rounded-lg bg-white/10 border border-white/30 text-white placeholder-gray-400 focus:outline-none focus:border-blue-400"
                  />
                  <button
                    onClick={sendChatMessage}
                    disabled={!newMessage.trim()}
                    className="px-6 py-3 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-lg hover:from-blue-600 hover:to-purple-700 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center"
                  >
                    <Send className="w-5 h-5" />
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default ChatApp;
