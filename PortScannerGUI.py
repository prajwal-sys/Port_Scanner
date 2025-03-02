import tkinter as tk
from tkinter import ttk, messagebox
import socket
import time
import threading
import mysql.connector
from concurrent.futures import ThreadPoolExecutor
import ttkthemes

class PortScannerGUI:
    def __init__(self):
        self.root = ttkthemes.ThemedTk()
        self.root.set_theme("arc")
        self.root.title("Port Scanner")
        self.root.geometry("800x600")
        
        self.colors = {
            'bg': '#2E3440',
            'fg': '#ECEFF4',
            'accent': '#88C0D0',
            'success': '#A3BE8C',
            'error': '#BF616A'
        }
        
        self.root.configure(bg=self.colors['bg'])
        self.current_user_id = None
        self.create_login_frame()
        
    def create_login_frame(self):
        self.clear_window()
        
        self.login_frame = ttk.Frame(self.root)
        self.login_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        title = ttk.Label(self.login_frame, text="Port Scanner Login", font=('Helvetica', 24))
        title.pack(pady=20)
        
        ttk.Label(self.login_frame, text="Username:").pack(pady=5)
        self.username_entry = ttk.Entry(self.login_frame)
        self.username_entry.pack(pady=5)
        
        ttk.Label(self.login_frame, text="Password:").pack(pady=5)
        self.password_entry = ttk.Entry(self.login_frame, show="*")
        self.password_entry.pack(pady=5)
        
        button_frame = ttk.Frame(self.login_frame)
        button_frame.pack(pady=20)
        
        ttk.Button(button_frame, text="Login", command=self.login).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Sign Up", command=self.create_signup_frame).pack(side=tk.LEFT, padx=10)
        
    def create_signup_frame(self):
        self.clear_window()
        
        self.signup_frame = ttk.Frame(self.root)
        self.signup_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        title = ttk.Label(self.signup_frame, text="Create Account", font=('Helvetica', 24))
        title.pack(pady=20)
        
        ttk.Label(self.signup_frame, text="Username:").pack(pady=5)
        self.new_username_entry = ttk.Entry(self.signup_frame)
        self.new_username_entry.pack(pady=5)
        
        ttk.Label(self.signup_frame, text="Password:").pack(pady=5)
        self.new_password_entry = ttk.Entry(self.signup_frame, show="*")
        self.new_password_entry.pack(pady=5)
        
        ttk.Label(self.signup_frame, text="Confirm Password:").pack(pady=5)
        self.confirm_password_entry = ttk.Entry(self.signup_frame, show="*")
        self.confirm_password_entry.pack(pady=5)
        
        button_frame = ttk.Frame(self.signup_frame)
        button_frame.pack(pady=20)
        
        ttk.Button(button_frame, text="Sign Up", command=self.signup).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Back to Login", command=self.create_login_frame).pack(side=tk.LEFT, padx=10)
        
    def create_main_frame(self):
        self.clear_window()
        
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        left_panel = ttk.Frame(self.main_frame)
        left_panel.pack(side=tk.LEFT, fill='both', expand=True, padx=10)
        
        ttk.Label(left_panel, text="Port Scanner", font=('Helvetica', 24)).pack(pady=20)
        
        input_frame = ttk.Frame(left_panel)
        input_frame.pack(fill='x', pady=10)
        
        ttk.Label(input_frame, text="Target:").pack()
        self.target_entry = ttk.Entry(input_frame)
        self.target_entry.pack(fill='x', pady=5)
        
        port_frame = ttk.Frame(input_frame)
        port_frame.pack(fill='x', pady=5)
        
        ttk.Label(port_frame, text="Start Port:").pack(side=tk.LEFT)
        self.start_port_entry = ttk.Entry(port_frame, width=10)
        self.start_port_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(port_frame, text="End Port:").pack(side=tk.LEFT)
        self.end_port_entry = ttk.Entry(port_frame, width=10)
        self.end_port_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(input_frame, text="Max Threads:").pack()
        self.threads_entry = ttk.Entry(input_frame)
        self.threads_entry.insert(0, "100")
        self.threads_entry.pack(fill='x', pady=5)
        
        button_frame = ttk.Frame(left_panel)
        button_frame.pack(fill='x', pady=20)
        
        ttk.Button(button_frame, text="Start Scan", command=self.start_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="View History", command=self.view_history).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Settings", command=self.show_settings).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Logout", command=self.logout).pack(side=tk.LEFT, padx=5)
        
        right_panel = ttk.Frame(self.main_frame)
        right_panel.pack(side=tk.RIGHT, fill='both', expand=True, padx=10)
        
        ttk.Label(right_panel, text="Scan Results", font=('Helvetica', 18)).pack(pady=10)
        
        self.results_text = tk.Text(right_panel, height=20, width=40)
        self.results_text.pack(fill='both', expand=True)
        
    def start_scan(self):
        try:
            target = self.target_entry.get()
            start_port = int(self.start_port_entry.get())
            end_port = int(self.end_port_entry.get())
            max_threads = int(self.threads_entry.get())
            
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, f"Starting scan on {target}...\n")
            
            scanner = PortScanner(
                target=target,
                start_port=start_port,
                end_port=end_port,
                max_threads=max_threads,
                user_id=self.current_user_id,
                gui_callback=self.update_results
            )
            
            threading.Thread(target=scanner.run_scan, daemon=True).start()
            
        except ValueError:
            messagebox.showerror("Error", "Please enter valid port numbers and thread count")
            
    def update_results(self, message):
        self.results_text.insert(tk.END, message + "\n")
        self.results_text.see(tk.END)
        
    def view_history(self):
        history_window = tk.Toplevel(self.root)
        history_window.title("Scan History")
        history_window.geometry("600x400")
        
        columns = ("Target", "Port", "Service", "Scan Time")
        tree = ttk.Treeview(history_window, columns=columns, show='headings')
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=140)
            
        scrollbar = ttk.Scrollbar(history_window, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        tree.pack(side=tk.LEFT, fill='both', expand=True)
        scrollbar.pack(side=tk.RIGHT, fill='y')
        
        db = connect_db()
        cursor = db.cursor()
        cursor.execute(
            "SELECT target, port, service, scan_time FROM scan_history WHERE user_id=%s ORDER BY scan_time DESC",
            (self.current_user_id,)
        )
        
        for record in cursor.fetchall():
            tree.insert("", tk.END, values=record)
            
        cursor.close()
        db.close()
        
    def show_settings(self):
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("400x300")
        
        ttk.Button(settings_window, text="Change Password", 
                  command=lambda: self.change_password_dialog(settings_window)).pack(pady=10)
        ttk.Button(settings_window, text="Delete Account", 
                  command=lambda: self.delete_account_dialog(settings_window)).pack(pady=10)
                  
    def change_password_dialog(self, parent):
        dialog = tk.Toplevel(parent)
        dialog.title("Change Password")
        dialog.geometry("300x400")
        
        ttk.Label(dialog, text="Current Password:").pack(pady=5)
        current_pass = ttk.Entry(dialog, show="*")
        current_pass.pack(pady=5)
        
        ttk.Label(dialog, text="New Password:").pack(pady=5)
        new_pass = ttk.Entry(dialog, show="*")
        new_pass.pack(pady=5)
        
        ttk.Label(dialog, text="Confirm New Password:").pack(pady=5)
        confirm_pass = ttk.Entry(dialog, show="*")
        confirm_pass.pack(pady=5)
        
        ttk.Button(dialog, text="Change Password", 
                  command=lambda: self.change_password(
                      current_pass.get(), new_pass.get(), confirm_pass.get(), dialog
                  )).pack(pady=10)
                  
    def delete_account_dialog(self, parent):
        dialog = tk.Toplevel(parent)
        dialog.title("Delete Account")
        dialog.geometry("300x150")
        
        ttk.Label(dialog, text="Enter password to confirm deletion:").pack(pady=10)
        password = ttk.Entry(dialog, show="*")
        password.pack(pady=10)
        
        ttk.Button(dialog, text="Delete Account", 
                  command=lambda: self.delete_account(password.get(), dialog)).pack(pady=10)
        
    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()
            
    def login(self):
        db = connect_db()
        cursor = db.cursor()
        
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        cursor.execute("SELECT id FROM users WHERE username=%s AND password=%s", (username, password))
        user = cursor.fetchone()
        
        cursor.close()
        db.close()
        
        if user:
            self.current_user_id = user[0]
            self.create_main_frame()
        else:
            messagebox.showerror("Error", "Invalid credentials")
            
    def signup(self):
        username = self.new_username_entry.get()
        password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
            
        db = connect_db()
        cursor = db.cursor()
        
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
            db.commit()
            messagebox.showinfo("Success", "Account created successfully!")
            self.create_login_frame()
        except mysql.connector.IntegrityError:
            messagebox.showerror("Error", "Username already exists")
        finally:
            cursor.close()
            db.close()
            
    def change_password(self, current_pass, new_pass, confirm_pass, dialog):
        if new_pass != confirm_pass:
            messagebox.showerror("Error", "New passwords do not match")
            return
            
        db = connect_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT password FROM users WHERE id=%s", (self.current_user_id,))
        stored_password = cursor.fetchone()
        
        if not stored_password or stored_password[0] != current_pass:
            messagebox.showerror("Error", "Current password is incorrect")
        else:
            cursor.execute("UPDATE users SET password=%s WHERE id=%s", (new_pass, self.current_user_id))
            db.commit()
            messagebox.showinfo("Success", "Password updated successfully")
            dialog.destroy()
            
        cursor.close()
        db.close()
        
    def delete_account(self, password, dialog):
        db = connect_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT password FROM users WHERE id=%s", (self.current_user_id,))
        stored_password = cursor.fetchone()
        
        if stored_password and stored_password[0] == password:
            cursor.execute("DELETE FROM users WHERE id=%s", (self.current_user_id,))
            db.commit()
            messagebox.showinfo("Success", "Account deleted successfully")
            dialog.destroy()
            self.logout()
        else:
            messagebox.showerror("Error", "Incorrect password")
            
        cursor.close()
        db.close()
        
    def logout(self):
        self.current_user_id = None
        self.create_login_frame()
        
    def run(self):
        self.root.mainloop()

def connect_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="port_scanner"
    )

class PortScanner:
    def __init__(self, target, start_port, end_port, max_threads=100, user_id=None, gui_callback=None):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.max_threads = max_threads
        self.open_ports = []
        self.lock = threading.Lock()
        self.gui_callback = gui_callback
        self.hostname = self.reverse_dns_lookup()
        self.user_id = user_id

    def reverse_dns_lookup(self):
        try:
            hostname = socket.gethostbyaddr(self.target)[0]
            if self.gui_callback:
                self.gui_callback(f"[*] Reverse DNS lookup: {self.target} → {hostname}")
            return hostname
        except socket.herror:
            if self.gui_callback:
                self.gui_callback(f"[*] No reverse DNS record found for {self.target}")
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
                    if self.gui_callback:
                        self.gui_callback(f"[+] Port {port} ({service_name}) is open")
        except Exception as e:
            if self.gui_callback:
                self.gui_callback(f"[-] Error scanning port {port}: {e}")

    def run_scan(self):
        start_time = time.time()
        if self.gui_callback:
            self.gui_callback(f"[*] Scanning target: {self.target} ({self.hostname if self.hostname else 'No hostname'})...")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.map(self.scan_port, range(self.start_port, self.end_port + 1))

        end_time = time.time()
        if self.gui_callback:
            self.gui_callback(f"[*] Scan completed in {end_time - start_time:.2f} seconds")
        
        self.save_scan_results()
    
    def save_scan_results(self):
        if not self.user_id:
            return
            
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
        
        if self.gui_callback:
            self.gui_callback("[+] Scan results saved to history.")

if __name__ == "__main__":
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
    
    app = PortScannerGUI()
    app.run()