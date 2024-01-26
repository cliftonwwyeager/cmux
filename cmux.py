import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import tkinter.simpledialog as simpledialog
import socket
import threading
import subprocess
import os
import sys
import requests

PORT = 22
RDP_PORT = 3389
VNC_PORTS = [5900, 5901]
VNC_VIEWER_DOWNLOAD_URL = "https://downloads.realvnc.com/download/file/viewer.files/VNC-Viewer-7.9.0-Windows.exe"

def add_remote_system():
    system_address = remote_system_entry.get().strip()
    if system_address:
        remote_systems_list.insert(tk.END, system_address)
        remote_system_entry.delete(0, tk.END)
    else:
        messagebox.showwarning("Warning", "Please enter a valid system address.")

def remove_selected_system():
    try:
        selected_indices = remote_systems_list.curselection()
        if not selected_indices:
            messagebox.showinfo("Info", "Please select a system to remove.")
            return
        for index in selected_indices[::-1]:
            remote_systems_list.delete(index)
    except Exception as e:
        messagebox.showerror("Error", f"Could not remove selected system: {e}")

def send_clipboard_contents():
    contents = root.clipboard_get()
    for idx in range(remote_systems_list.size()):
        system_address = remote_systems_list.get(idx)
        threading.Thread(
            target=send_to_remote_system, args=(system_address, contents)
        ).start()

def send_to_remote_system(system_address, contents):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((system_address, PORT))
            s.sendall(contents.encode())
    except Exception as e:
        messagebox.showerror("Error", f"Could not send data to {system_address}: {e}")

def connect_to_remote_desktop(system_address, protocol):
    try:
        if protocol == "VNC":
            connect_to_vnc(system_address)
        elif protocol == "RDP":
            if not is_tool("rdesktop"):
                messagebox.showerror("Error", "rdesktop is not installed. Please install it manually.")
                return
            command = ["rdesktop", system_address]
            subprocess.Popen(command)
        else:
            messagebox.showinfo("Info", "Invalid protocol selected.")
    except Exception as e:
        messagebox.showerror("Error", f"Error connecting to remote desktop: {e}")

def connect_to_vnc(system_address):
    if not is_tool("vncviewer"):
        messagebox.showinfo("Info", "VNC Viewer is not installed. Downloading now...")
        download_vnc_viewer()
        if not is_tool("vncviewer"):
            messagebox.showerror("Error", "Failed to install VNC Viewer. Please install it manually.")
            return
    try:
        command = ["vncviewer", system_address]
        subprocess.Popen(command)
    except Exception as e:
        messagebox.showerror("Error", f"Error connecting to VNC server: {e}")

def download_vnc_viewer():
    local_filename = VNC_VIEWER_DOWNLOAD_URL.split('/')[-1]
    with requests.get(VNC_VIEWER_DOWNLOAD_URL, stream=True) as r:
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    subprocess.run(local_filename, shell=True)

def is_tool(name):
    from shutil import which
    return which(name) is not None

def on_connect_remote_desktop():
    selected_indices = remote_systems_list.curselection()
    if selected_indices:
        system_address = remote_systems_list.get(selected_indices[0])
        protocol = simpledialog.askstring("Protocol", "Enter protocol (VNC or RDP):")
        if protocol:
            protocol = protocol.upper()
            if protocol in ["VNC", "RDP"]:
                connect_to_remote_desktop(system_address, protocol)
            else:
                messagebox.showerror("Error", "Invalid protocol. Please enter VNC or RDP.")
    else:
        messagebox.showinfo("Info", "Please select a system from the list.")

root = tk.Tk()
root.title("cMuX V1.1.1")

add_remote_frame = ttk.Frame(root)
add_remote_frame.pack(padx=10, pady=10)
ttk.Label(add_remote_frame, text="Add Remote System:").pack(side=tk.LEFT)
remote_system_entry = ttk.Entry(add_remote_frame)
remote_system_entry.pack(side=tk.LEFT)
ttk.Button(add_remote_frame, text="Add", command=add_remote_system).pack(side=tk.LEFT)
ttk.Button(add_remote_frame, text="Remove", command=remove_selected_system).pack(side=tk.LEFT)

remote_systems_list = tk.Listbox(root)
remote_systems_list.pack(padx=10, pady=10)

transfer_frame = ttk.Frame(root)
transfer_frame.pack(padx=10, pady=10)
ttk.Button(transfer_frame, text="Send Clipboard to All", command=send_clipboard_contents).pack()

remote_desktop_frame = ttk.Frame(root)
remote_desktop_frame.pack(padx=10, pady=10)
ttk.Button(remote_desktop_frame, text="Connect to Remote Desktop", command=on_connect_remote_desktop).pack()

root.mainloop()
