import socket
import time
import threading
import mysql.connector
from concurrent.futures import ThreadPoolExecutor
import getpass

class PortScanner:
    def __init__(self, target, start_port, end_port, max_threads=100, user_id=None):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.max_threads = max_threads
        self.open_ports = []
        self.lock = threading.Lock()
        self.hostname = self.reverse_dns_lookup()
        self.user_id = user_id

    def reverse_dns_lookup(self):
        try:
            hostname = socket.gethostbyaddr(self.target)[0]
            print(f"[*] Reverse DNS lookup: {self.target} → {hostname}\n")
            return hostname
        except socket.herror:
            print(f"[*] No reverse DNS record found for {self.target}\n")
            return None

    def get_service_name(self, port):
        try:
            return socket.getservbyport(port, 'tcp')
        except OSError:
            return "Unknown Service"

    def scan_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    service_name = self.get_service_name(port)
                    with self.lock:
                        self.open_ports.append((port, service_name))
                    print(f"[+] Port {port} ({service_name}) is open\n", flush=True)
        except Exception as e:
            print(f"[-] Error scanning port {port}: {e}")

    def run_scan(self):
        start_time = time.time()
        print(f"[*] Scanning target: {self.target} ({self.hostname if self.hostname else 'No hostname'})...\n")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.map(self.scan_port, range(self.start_port, self.end_port + 1))

        end_time = time.time()
        print(f"[*] Scan completed in {end_time - start_time:.2f} seconds\n")
        
        self.save_scan_results()
    
    def save_scan_results(self):
        db = connect_db()
        cursor = db.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                target VARCHAR(255) NOT NULL,
                port INT NOT NULL,
                service VARCHAR(100),
                scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        for port, service in self.open_ports:
            cursor.execute("""
                INSERT INTO scan_history (user_id, target, port, service) 
                VALUES (%s, %s, %s, %s)
            """, (self.user_id, self.target, port, service))
        
        db.commit()
        cursor.close()
        db.close()
        print("[+] Scan results saved to history.\n")

def connect_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="port_scanner"
    )

def create_tables():
    db = connect_db()
    cursor = db.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            target VARCHAR(255) NOT NULL,
            port INT NOT NULL,
            service VARCHAR(100),
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    db.commit()
    cursor.close()
    db.close()

def sign_up():
    db = connect_db()
    cursor = db.cursor()

    username = input("Enter new username: ")
    
    while True:
        password = getpass.getpass("Enter new password: ")
        confirm_password = getpass.getpass("Confirm password: ")
        
        if password == confirm_password:
            break
        else:
            print("[-] Passwords do not match. Please try again.")

    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
        db.commit()
        print("[+] User registered successfully!\n")
    except mysql.connector.IntegrityError:
        print("[-] Username already exists.\n")

    cursor.close()
    db.close()


def log_in():
    db = connect_db()
    cursor = db.cursor()
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    cursor.execute("SELECT id FROM users WHERE username=%s AND password=%s", (username, password))
    user = cursor.fetchone()
    cursor.close()
    db.close()

    if user:
        print("[+] Login successful!\n")
        user_id = user[0]
        
        while True:
            print("\n=== User Menu ===")
            print("1. Start Port Scanning")
            print("2. View Scan History")
            print("3. Change Password")
            print("4. Delete Account")
            print("5. Log Out")
            choice = input("Enter your choice: ")
            
            if choice == "1":
                start_port_scan(user_id)
            elif choice == "2":
                view_scan_history(user_id)
            elif choice == "3":
                change_password(user_id)
            elif choice == "4":
                delete_account(user_id)
                return None
            elif choice == "5":
                print("[+] Logging out...\n")
                return None
            else:
                print("[-] Invalid choice. Please try again.")
    else:
        print("[-] Invalid credentials.\n")
        return None

    
def change_password(user_id):
    db = connect_db()
    cursor = db.cursor()

    current_password = getpass.getpass("Enter current password: ")
    
    cursor.execute("SELECT password FROM users WHERE id=%s", (user_id,))
    stored_password = cursor.fetchone()

    if not stored_password or stored_password[0] != current_password:
        print("[-] Incorrect current password. Password change canceled.\n")
        cursor.close()
        db.close()
        return
    
    while True:
        new_password = getpass.getpass("Enter new password: ")
        confirm_password = getpass.getpass("Confirm new password: ")
        
        if new_password == confirm_password:
            break
        else:
            print("[-] Passwords do not match. Please try again.")

    cursor.execute("UPDATE users SET password=%s WHERE id=%s", (new_password, user_id))
    db.commit()
    cursor.close()
    db.close()
    
    print("[+] Password updated successfully!\n")

def delete_account(user_id):
    db = connect_db()
    cursor = db.cursor()
    
    confirm = input("Are you sure you want to delete your account? (yes/no): ").strip().lower()
    if confirm == "yes":
        password = getpass.getpass("Please enter your password to confirm account deletion: ")

        cursor.execute("SELECT password FROM users WHERE id=%s", (user_id,))
        stored_password = cursor.fetchone()
        
        if stored_password and stored_password[0] == password:
            cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
            cursor.execute("DELETE FROM scan_history WHERE user_id=%s", (user_id,))
            db.commit()
            print("[+] Account deleted successfully.\n")
        else:
            print("[-] Incorrect password. Account deletion canceled.\n")
    else:
        print("[-] Account deletion canceled.")
    
    cursor.close()
    db.close()



def view_scan_history(user_id):
    db = connect_db()
    cursor = db.cursor()
    cursor.execute("SELECT target, port, service, scan_time FROM scan_history WHERE user_id=%s ORDER BY scan_time DESC", (user_id,))
    history = cursor.fetchall()
    cursor.close()
    db.close()
    
    if history:
        print("\n=== Scan History ===")
        for record in history:
            print(f"Target: {record[0]}, Port: {record[1]}, Service: {record[2]}, Time: {record[3]}")
    else:
        print("\n[-] No scan history found.")


def main_menu():
    create_tables()
    while True:
        print("\n=== Port Scanner Menu ===")
        print("1. Sign Up")
        print("2. Log In")
        print("3. Exit")
        choice = input("Enter your choice: ")
        
        if choice == "1":
            sign_up()
        elif choice == "2":
            log_in()
        elif choice == "3":
            print("Exiting program. Goodbye!")
            break
        else:
            print("[-] Invalid choice. Please try again.")

def start_port_scan(user_id):
    target = input("Enter target IP address or hostname: ")
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))
    max_threads = int(input("Enter maximum threads (default 100): ") or 100)
    
    scanner = PortScanner(target, start_port, end_port, max_threads, user_id)
    scanner.run_scan()

if __name__ == "__main__":
    main_menu()
