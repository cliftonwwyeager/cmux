import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import socket
import threading
import subprocess
import os
import requests
import win32clipboard
import win32con
import win32com.client
import winrm

PORT = 22
RDP_PORT = 3389
VNC_PORTS = [5900, 5901]
VNC_VIEWER_DOWNLOAD_URL = "https://downloads.realvnc.com/download/file/vnc.files/VNC-Connect-Installer-2.3.0-Windows.exe"

class ClipboardMultiplexer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("cMuX V1.1.4")
        self.geometry("800x600")
        self.configure(bg='black')
        self.style = ttk.Style()
        self.style.configure('Custom.TFrame', background='black')
        self.style.configure('Custom.TLabel', background='black', foreground='#00FF00')
        self.style.configure('Custom.TEntry', fieldbackground='black', foreground='#00FF00')
        self.style.configure('Custom.TButton', background='black', foreground='#00FF00')
        self.style.configure('Custom.TMenubutton', background='black', foreground='#00FF00')
        self.style.configure('Custom.TListbox', background='black', foreground='#00FF00')

        self.remote_systems = []
        self.create_widgets()

    def create_widgets(self):
        self.create_add_remote_frame()
        self.create_remote_systems_list()
        self.create_transfer_frame()
        self.create_clipboard_menu()

    def create_add_remote_frame(self):
        add_remote_frame = ttk.Frame(self, style='Custom.TFrame')
        add_remote_frame.pack(padx=10, pady=10, fill=tk.X)

        label = ttk.Label(add_remote_frame, text="Add Remote System:", style='Custom.TLabel')
        label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.remote_system_entry = ttk.Entry(add_remote_frame, style='Custom.TEntry')
        self.remote_system_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))
        
        add_button = ttk.Button(add_remote_frame, text="Add", command=self.add_remote_system, style='Custom.TButton')
        add_button.pack(side=tk.LEFT, padx=(0, 5))
        
        remove_button = ttk.Button(add_remote_frame, text="Remove", command=self.remove_selected_system, style='Custom.TButton')
        remove_button.pack(side=tk.LEFT)

    def create_remote_systems_list(self):
        list_frame = ttk.Frame(self, style='Custom.TFrame')
        list_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.remote_systems_list = tk.Listbox(list_frame, selectmode=tk.SINGLE, bg='black', fg='#00FF00')
        self.remote_systems_list.pack(fill=tk.BOTH, expand=True)

    def create_transfer_frame(self):
        transfer_frame = ttk.Frame(self, style='Custom.TFrame')
        transfer_frame.pack(padx=10, pady=10, fill=tk.X)
        
        send_clipboard_button = ttk.Button(transfer_frame, text="Send Clipboard to All", command=self.send_clipboard_contents, style='Custom.TButton')
        send_clipboard_button.pack(side=tk.LEFT, padx=(0, 5))

        send_file_button = ttk.Button(transfer_frame, text="Send Clipboard File to All", command=self.send_clipboard_file, style='Custom.TButton')
        send_file_button.pack(side=tk.LEFT, padx=(0, 5))

    def create_clipboard_menu(self):
        menu = tk.Menu(self, bg='black', fg='#00FF00', tearoff=0)
        self.config(menu=menu)
        clipboard_menu = tk.Menu(menu, bg='black', fg='#00FF00', tearoff=0)
        menu.add_cascade(label="Clipboard", menu=clipboard_menu)
        clipboard_menu.add_command(label="Paste into Current Session", command=self.paste_clipboard_current)
        clipboard_menu.add_command(label="Paste into All Sessions", command=self.paste_clipboard_all)

    def add_remote_system(self):
        system_address = self.remote_system_entry.get().strip()
        if system_address and system_address not in self.remote_systems:
            self.remote_systems.append(system_address)
            self.remote_systems_list.insert(tk.END, system_address)
            self.remote_system_entry.delete(0, tk.END)
        else:
            messagebox.showwarning("Warning", "Please enter a valid system address.")

    def remove_selected_system(self):
        selected_indices = self.remote_systems_list.curselection()
        if not selected_indices:
            messagebox.showinfo("Info", "Please select a system to remove.")
            return
        for index in selected_indices[::-1]:
            self.remote_systems.pop(index)
            self.remote_systems_list.delete(index)

    def send_clipboard_contents(self):
        try:
            contents = self.clipboard_get()
        except tk.TclError:
            messagebox.showerror("Error", "Failed to get clipboard contents.")
            return

        for system_address in self.remote_systems:
            threading.Thread(target=self.send_to_remote_system, args=(system_address, contents)).start()

    def send_clipboard_file(self):
        username = simpledialog.askstring("Username", "Enter username:", show='*')
        if not username:
            return
        password = simpledialog.askstring("Password", "Enter password:", show='*')
        if not password:
            return

        file_path = self.get_clipboard_file()
        if file_path:
            for system_address in self.remote_systems:
                threading.Thread(target=self.send_file_to_remote_system, args=(system_address, file_path, username, password)).start()

    def get_clipboard_file(self):
        try:
            win32clipboard.OpenClipboard()
            data = win32clipboard.GetClipboardData(win32con.CF_HDROP)
            win32clipboard.CloseClipboard()
            if data:
                return data[0]
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get file from clipboard: {e}")
            return None

    def send_file_to_remote_system(self, system_address, file_path, username, password):
        try:
            session = winrm.Session(f'http://{system_address}:5985/wsman', auth=(username, password))
            with open(file_path, 'rb') as f:
                file_content = f.read()
            encoded_content = file_content.encode('base64')
            script = f"$content = [System.Convert]::FromBase64String('{encoded_content}'); [System.IO.File]::WriteAllBytes('{file_path}', $content)"
            session.run_ps(script)
        except Exception as e:
            self.report_error(f"Could not send file to {system_address}: {e}")

    def send_to_remote_system(self, system_address, contents):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((system_address, PORT))
                s.sendall(contents.encode())
        except Exception as e:
            self.report_error(f"Could not send data to {system_address}: {e}")

    def paste_clipboard_current(self):
        try:
            contents = self.clipboard_get()
            selected_index = self.remote_systems_list.curselection()
            if selected_index:
                current_system = self.remote_systems_list.get(selected_index)
                self.send_to_remote_system(current_system, contents)
            else:
                messagebox.showinfo("Info", "Please select a system to paste clipboard.")
        except tk.TclError:
            messagebox.showerror("Error", "Failed to get clipboard contents.")

    def paste_clipboard_all(self):
        self.send_clipboard_contents()

    def report_error(self, message):
        self.after(0, messagebox.showerror, "Error", message)

if __name__ == "__main__":
    app = ClipboardMultiplexer()
    app.mainloop()
