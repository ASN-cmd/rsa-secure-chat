"""
Database Management Utility for RSA Chat Server
This utility helps manage the persistent database for the chat server.
"""

import sqlite3
import argparse
import json
import hashlib
from datetime import datetime
from tabulate import tabulate


class ChatDBManager:
    def __init__(self, db_path="chat_server.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
    
    def close(self):
        if self.conn:
            self.conn.close()
    
    def get_stats(self):
        """Get database statistics"""
        cursor = self.conn.execute("SELECT COUNT(*) as count FROM users")
        user_count = cursor.fetchone()['count']
        
        cursor = self.conn.execute("SELECT COUNT(*) as count FROM messages")
        message_count = cursor.fetchone()['count']
        
        cursor = self.conn.execute("SELECT COUNT(*) as count FROM friendships")
        friendship_count = cursor.fetchone()['count']
        
        cursor = self.conn.execute("SELECT COUNT(*) as count FROM messages WHERE delivered = FALSE")
        pending_count = cursor.fetchone()['count']
        
        return {
            'users': user_count,
            'messages': message_count,
            'friendships': friendship_count,
            'pending_messages': pending_count
        }
    
    def list_users(self):
        """List all users"""
        cursor = self.conn.execute("""
            SELECT username, created_at, last_login, 
                   CASE WHEN public_key IS NOT NULL THEN 'Yes' ELSE 'No' END as has_key
            FROM users 
            ORDER BY username
        """)
        
        users = cursor.fetchall()
        if users:
            headers = ['Username', 'Created At', 'Last Login', 'Has Public Key']
            rows = []
            for user in users:
                rows.append([
                    user['username'],
                    user['created_at'],
                    user['last_login'] or 'Never',
                    user['has_key']
                ])
            print(tabulate(rows, headers=headers, tablefmt='grid'))
        else:
            print("No users found.")
    
    def list_friendships(self):
        """List all friendships"""
        cursor = self.conn.execute("""
            SELECT u1.username as user, u2.username as friend, f.created_at
            FROM friendships f
            JOIN users u1 ON f.user_id = u1.id
            JOIN users u2 ON f.friend_id = u2.id
            ORDER BY u1.username, u2.username
        """)
        
        friendships = cursor.fetchall()
        if friendships:
            headers = ['User', 'Friend', 'Since']
            rows = [[f['user'], f['friend'], f['created_at']] for f in friendships]
            print(tabulate(rows, headers=headers, tablefmt='grid'))
        else:
            print("No friendships found.")
    
    def list_messages(self, username=None, limit=50):
        """List messages, optionally filtered by username"""
        if username:
            cursor = self.conn.execute("""
                SELECT u1.username as from_user, u2.username as to_user, 
                       m.timestamp, m.delivered, 
                       SUBSTR(m.encrypted_message, 1, 50) || '...' as message_preview
                FROM messages m
                JOIN users u1 ON m.from_user_id = u1.id
                JOIN users u2 ON m.to_user_id = u2.id
                WHERE u1.username = ? OR u2.username = ?
                ORDER BY m.timestamp DESC
                LIMIT ?
            """, (username, username, limit))
        else:
            cursor = self.conn.execute("""
                SELECT u1.username as from_user, u2.username as to_user, 
                       m.timestamp, m.delivered,
                       SUBSTR(m.encrypted_message, 1, 50) || '...' as message_preview
                FROM messages m
                JOIN users u1 ON m.from_user_id = u1.id
                JOIN users u2 ON m.to_user_id = u2.id
                ORDER BY m.timestamp DESC
                LIMIT ?
            """, (limit,))
        
        messages = cursor.fetchall()
        if messages:
            headers = ['From', 'To', 'Timestamp', 'Delivered', 'Preview']
            rows = []
            for msg in messages:
                rows.append([
                    msg['from_user'],
                    msg['to_user'],
                    msg['timestamp'],
                    'Yes' if msg['delivered'] else 'No',
                    msg['message_preview']
                ])
            print(tabulate(rows, headers=headers, tablefmt='grid'))
        else:
            print("No messages found.")
    
    def delete_user(self, username):
        """Delete a user and all associated data"""
        cursor = self.conn.execute("SELECT id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if not user:
            print(f"User '{username}' not found.")
            return
        
        # Due to foreign key constraints, this will cascade delete
        self.conn.execute("DELETE FROM users WHERE username = ?", (username,))
        self.conn.commit()
        print(f"User '{username}' and all associated data deleted.")
    
    def clear_messages(self, older_than_days=None):
        """Clear messages, optionally only older than specified days"""
        if older_than_days:
            self.conn.execute("""
                DELETE FROM messages 
                WHERE timestamp < datetime('now', '-{} days')
            """.format(older_than_days))
        else:
            self.conn.execute("DELETE FROM messages")
        
        deleted = self.conn.total_changes
        self.conn.commit()
        print(f"Deleted {deleted} messages.")
    
    def reset_database(self):
        """Reset the entire database"""
        confirm = input("Are you sure you want to reset the entire database? This cannot be undone. (yes/no): ")
        if confirm.lower() == 'yes':
            self.conn.execute("DELETE FROM messages")
            self.conn.execute("DELETE FROM friendships")
            self.conn.execute("DELETE FROM users")
            self.conn.commit()
            print("Database reset complete.")
        else:
            print("Reset cancelled.")
    
    def export_data(self, output_file):
        """Export all data to JSON file"""
        data = {
            'users': [],
            'friendships': [],
            'messages': []
        }
        
        # Export users (without password hashes for security)
        cursor = self.conn.execute("SELECT username, created_at, last_login FROM users")
        data['users'] = [dict(row) for row in cursor.fetchall()]
        
        # Export friendships
        cursor = self.conn.execute("""
            SELECT u1.username as user, u2.username as friend, f.created_at
            FROM friendships f
            JOIN users u1 ON f.user_id = u1.id
            JOIN users u2 ON f.friend_id = u2.id
        """)
        data['friendships'] = [dict(row) for row in cursor.fetchall()]
        
        # Export message metadata (not the encrypted content for security)
        cursor = self.conn.execute("""
            SELECT u1.username as from_user, u2.username as to_user, 
                   m.timestamp, m.delivered
            FROM messages m
            JOIN users u1 ON m.from_user_id = u1.id
            JOIN users u2 ON m.to_user_id = u2.id
        """)
        data['messages'] = [dict(row) for row in cursor.fetchall()]
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        print(f"Data exported to {output_file}")
    
    def create_user(self, username, password):
        """Create a new user account"""
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            self.conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
            self.conn.commit()
            print(f"User '{username}' created successfully.")
        except sqlite3.IntegrityError:
            print(f"Error: Username '{username}' already exists.")
    
    def change_password(self, username, new_password):
        """Change a user's password"""
        cursor = self.conn.execute("SELECT id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if not user:
            print(f"User '{username}' not found.")
            return
        
        password_hash = hashlib.sha256(new_password.encode()).hexdigest()
        self.conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (password_hash, username)
        )
        self.conn.commit()
        print(f"Password changed for user '{username}'.")


def main():
    parser = argparse.ArgumentParser(description='Chat Database Manager')
    parser.add_argument('--db', default='chat_server.db', help='Database file path')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Stats command
    subparsers.add_parser('stats', help='Show database statistics')
    
    # List commands
    subparsers.add_parser('users', help='List all users')
    subparsers.add_parser('friends', help='List all friendships')
    
    # Messages command
    msg_parser = subparsers.add_parser('messages', help='List messages')
    msg_parser.add_argument('--user', help='Filter by username')
    msg_parser.add_argument('--limit', type=int, default=50, help='Limit number of results')
    
    # Delete user command
    del_parser = subparsers.add_parser('delete-user', help='Delete a user')
    del_parser.add_argument('username', help='Username to delete')
    
    # Clear messages command
    clear_parser = subparsers.add_parser('clear-messages', help='Clear messages')
    clear_parser.add_argument('--days', type=int, help='Only clear messages older than N days')
    
    # Reset command
    subparsers.add_parser('reset', help='Reset entire database')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export data to JSON')
    export_parser.add_argument('output', help='Output file path')
    
    # Create user command
    create_parser = subparsers.add_parser('create-user', help='Create new user')
    create_parser.add_argument('username', help='Username')
    create_parser.add_argument('password', help='Password')
    
    # Change password command
    pwd_parser = subparsers.add_parser('change-password', help='Change user password')
    pwd_parser.add_argument('username', help='Username')
    pwd_parser.add_argument('password', help='New password')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        db = ChatDBManager(args.db)
        
        if args.command == 'stats':
            stats = db.get_stats()
            print("Database Statistics:")
            print(f"Users: {stats['users']}")
            print(f"Friendships: {stats['friendships']}")
            print(f"Total Messages: {stats['messages']}")
            print(f"Pending Messages: {stats['pending_messages']}")
        
        elif args.command == 'users':
            db.list_users()
        
        elif args.command == 'friends':
            db.list_friendships()
        
        elif args.command == 'messages':
            db.list_messages(args.user, args.limit)
        
        elif args.command == 'delete-user':
            db.delete_user(args.username)
        
        elif args.command == 'clear-messages':
            db.clear_messages(args.days)
        
        elif args.command == 'reset':
            db.reset_database()
        
        elif args.command == 'export':
            db.export_data(args.output)
        
        elif args.command == 'create-user':
            db.create_user(args.username, args.password)
        
        elif args.command == 'change-password':
            db.change_password(args.username, args.password)
        
        db.close()
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()