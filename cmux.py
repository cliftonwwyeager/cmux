import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import socket
import threading
import subprocess
import os
import requests

PORT = 22
RDP_PORT = 3389
VNC_PORTS = [5900, 5901]
VNC_VIEWER_DOWNLOAD_URL = "https://downloads.realvnc.com/download/file/vnc.files/VNC-Connect-Installer-2.3.0-Windows.exe"

class ClipboardMultiplexer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("cMuX V1.1.2")
        self.create_widgets()

    def create_widgets(self):
        self.create_add_remote_frame()
        self.create_remote_systems_list()
        self.create_transfer_frame()
        self.create_remote_desktop_frame()

    def create_add_remote_frame(self):
        add_remote_frame = ttk.Frame(self)
        add_remote_frame.pack(padx=10, pady=10)

        ttk.Label(add_remote_frame, text="Add Remote System:").pack(side=tk.LEFT)
        self.remote_system_entry = ttk.Entry(add_remote_frame)
        self.remote_system_entry.pack(side=tk.LEFT)
        ttk.Button(add_remote_frame, text="Add", command=self.add_remote_system).pack(side=tk.LEFT)
        ttk.Button(add_remote_frame, text="Remove", command=self.remove_selected_system).pack(side=tk.LEFT)

    def create_remote_systems_list(self):
        self.remote_systems_list = tk.Listbox(self)
        self.remote_systems_list.pack(padx=10, pady=10)

    def create_transfer_frame(self):
        transfer_frame = ttk.Frame(self)
        transfer_frame.pack(padx=10, pady=10)
        ttk.Button(transfer_frame, text="Send Clipboard to All", command=self.send_clipboard_contents).pack()

    def create_remote_desktop_frame(self):
        remote_desktop_frame = ttk.Frame(self)
        remote_desktop_frame.pack(padx=10, pady=10)
        ttk.Button(remote_desktop_frame, text="Connect to Remote Desktop", command=self.on_connect_remote_desktop).pack()

    def add_remote_system(self):
        system_address = self.remote_system_entry.get().strip()
        if system_address:
            self.remote_systems_list.insert(tk.END, system_address)
            self.remote_system_entry.delete(0, tk.END)
        else:
            messagebox.showwarning("Warning", "Please enter a valid system address.")

    def remove_selected_system(self):
        try:
            selected_indices = self.remote_systems_list.curselection()
            if not selected_indices:
                messagebox.showinfo("Info", "Please select a system to remove.")
                return
            for index in selected_indices[::-1]:
                self.remote_systems_list.delete(index)
        except Exception as e:
            messagebox.showerror("Error", f"Could not remove selected system: {e}")

    def send_clipboard_contents(self):
        try:
            contents = self.clipboard_get()
        except tk.TclError:
            messagebox.showerror("Error", "Failed to get clipboard contents.")
            return

        for idx in range(self.remote_systems_list.size()):
            system_address = self.remote_systems_list.get(idx)
            threading.Thread(target=self.send_to_remote_system, args=(system_address, contents)).start()

    def send_to_remote_system(self, system_address, contents):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((system_address, PORT))
                s.sendall(contents.encode())
        except Exception as e:
            self.report_error(f"Could not send data to {system_address}: {e}")

    def on_connect_remote_desktop(self):
        selected_indices = self.remote_systems_list.curselection()
        if selected_indices:
            system_address = self.remote_systems_list.get(selected_indices[0])
            protocol = simpledialog.askstring("Protocol", "Enter protocol (VNC or RDP):")
            if protocol:
                protocol = protocol.upper()
                if protocol in ["VNC", "RDP"]:
                    self.connect_to_remote_desktop(system_address, protocol)
                else:
                    messagebox.showerror("Error", "Invalid protocol. Please enter VNC or RDP.")
        else:
            messagebox.showinfo("Info", "Please select a system from the list.")

    def connect_to_remote_desktop(self, system_address, protocol):
        try:
            if protocol == "VNC":
                self.connect_to_vnc(system_address)
            elif protocol == "RDP":
                if not self.is_tool("rdesktop"):
                    messagebox.showerror("Error", "rdesktop is not installed. Please install it manually.")
                    return
                command = ["rdesktop", system_address]
                subprocess.Popen(command)
        except Exception as e:
            self.report_error(f"Error connecting to remote desktop: {e}")

    def connect_to_vnc(self, system_address):
        if not self.is_tool("vncviewer"):
            messagebox.showinfo("Info", "VNC Viewer is not installed. Downloading now...")
            self.download_vnc_viewer()
            if not self.is_tool("vncviewer"):
                messagebox.showerror("Error", "Failed to install VNC Viewer. Please install it manually.")
                return
        try:
            command = ["vncviewer", system_address]
            subprocess.Popen(command)
        except Exception as e:
            self.report_error(f"Error connecting to VNC server: {e}")

    def download_vnc_viewer(self):
        local_filename = VNC_VIEWER_DOWNLOAD_URL.split('/')[-1]
        try:
            with requests.get(VNC_VIEWER_DOWNLOAD_URL, stream=True) as r:
                r.raise_for_status()
                with open(local_filename, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
            subprocess.run(local_filename, shell=True)
        except requests.RequestException as e:
            self.report_error(f"Failed to download VNC Viewer: {e}")

    def is_tool(self, name):
        from shutil import which
        return which(name) is not None

    def report_error(self, message):
        self.after(0, messagebox.showerror, "Error", message)

if __name__ == "__main__":
    app = ClipboardMultiplexer()
    app.mainloop()
