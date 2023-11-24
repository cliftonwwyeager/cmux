import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import socket
import threading
import subprocess
import os

def add_remote_system():
    system_address = remote_system_entry.get().strip()
    if system_address:
        remote_systems_list.insert(tk.END, system_address)
        remote_system_entry.delete(0, tk.END)
    else:
        messagebox.showwarning("Warning", "Please enter a valid system address.")

def send_clipboard_contents():
    contents = root.clipboard_get()
    for idx in range(remote_systems_list.size()):
        system_address = remote_systems_list.get(idx)
        threading.Thread(target=send_to_remote_system, args=(system_address, contents)).start()

def send_to_remote_system(system_address, contents):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((system_address, PORT))  # PORT should be defined
            s.sendall(contents.encode())
    except Exception as e:
        messagebox.showerror("Error", f"Could not send data to {system_address}: {e}")
        
def connect_to_remote_desktop(system_address):
    try:
        # Ensure the rdesktop is installed
        if not is_tool("rdesktop"):
            raise EnvironmentError("rdesktop is not installed")

        # Command to start an rdesktop session
        command = ["rdesktop", system_address]
        
        # Launch the rdesktop in a subprocess
        subprocess.Popen(command)
    except Exception as e:
        print(f"Error connecting to remote desktop: {e}")

def is_tool(name):
    """Check whether `name` is on PATH and marked as executable."""
    from shutil import which
    return which(name) is not None

# Setting up the GUI
root = tk.Tk()
root.title("Clipboard Multiplexer and Remote Control")

# Add remote system section
add_remote_frame = ttk.Frame(root)
add_remote_frame.pack(padx=10, pady=10)

ttk.Label(add_remote_frame, text="Add Remote System:").pack(side=tk.LEFT)
remote_system_entry = ttk.Entry(add_remote_frame)
remote_system_entry.pack(side=tk.LEFT)
ttk.Button(add_remote_frame, text="Add", command=add_remote_system).pack(side=tk.LEFT)

remote_systems_list = tk.Listbox(root)
remote_systems_list.pack(padx=10, pady=10)

# Clipboard and file transfer section
transfer_frame = ttk.Frame(root)
transfer_frame.pack(padx=10, pady=10)

ttk.Button(transfer_frame, text="Send Clipboard to All", command=send_clipboard_contents).pack()

# Remote desktop section
remote_desktop_frame = ttk.Frame(root)
remote_desktop_frame.pack(padx=10, pady=10)

ttk.Button(remote_desktop_frame, text="Connect to Remote Desktop", command=connect_to_remote_desktop).pack()

root.mainloop()
