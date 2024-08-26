import tkinter as tk
from tkinter import ttk, messagebox, Toplevel, StringVar, BooleanVar
import socket
import threading
import subprocess
import os
import requests
import base64
import pyperclip
import winrm

PORT = 22
RDP_PORT = 3389
VNC_PORTS = [5900, 5901]
VNC_VIEWER_DOWNLOAD_URL = "https://downloads.realvnc.com/download/file/vnc.files/VNC-Connect-Installer-7.12.1-Windows.exe"

class CredentialsDialog(Toplevel):
    def __init__(self, parent, on_store_callback):
        super().__init__(parent)
        self.title("Enter Credentials")
        self.geometry("300x150")
        self.configure(bg='black')

        self.on_store_callback = on_store_callback
        self.username_var = StringVar()
        self.password_var = StringVar()
        self.show_password_var = BooleanVar()

        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self, text="Username:", style='Custom.TLabel').pack(pady=5)
        ttk.Entry(self, textvariable=self.username_var, style='Custom.TEntry').pack(pady=5)
        
        ttk.Label(self, text="Password:", style='Custom.TLabel').pack(pady=5)
        ttk.Entry(self, textvariable=self.password_var, style='Custom.TEntry', show='*').pack(pady=5)
        
        ttk.Checkbutton(self, text="Show Password", variable=self.show_password_var, style='Custom.TCheckbutton', command=self.toggle_password).pack(pady=5)

        button_frame = ttk.Frame(self, style='Custom.TFrame')
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="Store", command=self.on_store, style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Cancel", command=self.on_cancel, style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 5))

    def toggle_password(self):
        self.password_entry.config(show='' if self.show_password_var.get() else '*')

    def on_store(self):
        username = self.username_var.get()
        password = self.password_var.get()
        if username and password:
            self.on_store_callback(username, password)
            self.destroy()
        else:
            messagebox.showwarning("Warning", "Please enter both username and password.")

    def on_cancel(self):
        self.destroy()


class ClipboardMultiplexer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("cMuX V1.1.8")
        self.geometry("1000x600")
        self.configure(bg='black')
        
        self.style = self.create_styles()

        self.remote_systems = []
        self.active_sessions = {}
        self.credentials_store = []

        self.create_widgets()

    def create_styles(self):
        style = ttk.Style()
        style.configure('Custom.TFrame', background='black')
        style.configure('Custom.TLabel', background='black', foreground='#00FF00')
        style.configure('Custom.TEntry', fieldbackground='black', foreground='#00FF00')
        style.configure('Custom.TButton', background='black', foreground='#00FF00')
        style.configure('Custom.TMenubutton', background='black', foreground='#00FF00')
        style.configure('Custom.TListbox', background='black', foreground='#00FF00')
        style.configure('Custom.TCheckbutton', background='black', foreground='#00FF00')
        style.configure('Custom.TCombobox', fieldbackground='black', foreground='#00FF00')
        return style

    def create_widgets(self):
        self.create_add_remote_frame()
        self.create_remote_systems_list()
        self.create_transfer_frame()
        self.create_clipboard_menu()
        self.create_session_sidebar()
        self.create_credentials_store()

    def create_add_remote_frame(self):
        frame = ttk.Frame(self, style='Custom.TFrame')
        frame.pack(padx=10, pady=10, fill=tk.X)

        ttk.Label(frame, text="Add Remote System:", style='Custom.TLabel').pack(side=tk.LEFT, padx=(0, 5))
        
        self.remote_system_entry = ttk.Entry(frame, style='Custom.TEntry')
        self.remote_system_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))
        
        ttk.Button(frame, text="Add", command=self.add_remote_system, style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(frame, text="Remove", command=self.remove_selected_system, style='Custom.TButton').pack(side=tk.LEFT)

    def create_remote_systems_list(self):
        frame = ttk.Frame(self, style='Custom.TFrame')
        frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.remote_systems_list = tk.Listbox(frame, selectmode=tk.SINGLE, bg='black', fg='#00FF00')
        self.remote_systems_list.pack(fill=tk.BOTH, expand=True)

    def create_transfer_frame(self):
        frame = ttk.Frame(self, style='Custom.TFrame')
        frame.pack(padx=10, pady=10, fill=tk.X)

        ttk.Button(frame, text="Send Clipboard to All", command=self.send_clipboard_contents, style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(frame, text="Send Clipboard File to All", command=self.send_clipboard_file, style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(frame, text="Connect RDP", command=self.connect_rdp, style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(frame, text="Connect VNC", command=self.connect_vnc, style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 5))

    def create_clipboard_menu(self):
        menu = tk.Menu(self, bg='black', fg='#00FF00', tearoff=0)
        self.config(menu=menu)
        clipboard_menu = tk.Menu(menu, bg='black', fg='#00FF00', tearoff=0)
        menu.add_cascade(label="Clipboard", menu=clipboard_menu)
        clipboard_menu.add_command(label="Paste into Current Session", command=self.paste_clipboard_current)
        clipboard_menu.add_command(label="Paste into All Sessions", command=self.paste_clipboard_all)

    def create_session_sidebar(self):
        frame = ttk.Frame(self, style='Custom.TFrame')
        frame.pack(side=tk.RIGHT, fill=tk.Y, padx=10, pady=10)

        ttk.Label(frame, text="Active Sessions:", style='Custom.TLabel').pack()

        self.session_list = tk.Listbox(frame, selectmode=tk.SINGLE, bg='black', fg='#00FF00')
        self.session_list.pack(fill=tk.BOTH, expand=True)

        self.session_list.bind('<<ListboxSelect>>', self.bring_session_to_foreground)

    def create_credentials_store(self):
        frame = ttk.Frame(self, style='Custom.TFrame')
        frame.pack(padx=10, pady=10, fill=tk.X)

        ttk.Button(frame, text="Add Credentials", command=self.add_credentials, style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(frame, text="Remove Credentials", command=self.remove_selected_credential, style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 5))

        self.credentials_list = tk.Listbox(frame, selectmode=tk.SINGLE, bg='black', fg='#00FF00')
        self.credentials_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))

        ttk.Label(frame, text="Select Credentials:", style='Custom.TLabel').pack(side=tk.LEFT)

        self.selected_credentials = StringVar()
        self.credentials_combobox = ttk.Combobox(frame, textvariable=self.selected_credentials, style='Custom.TCombobox', state='readonly')
        self.credentials_combobox.pack(fill=tk.X)

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
        contents = pyperclip.paste()
        if not contents:
            messagebox.showerror("Error", "Clipboard is empty.")
            return

        for system_address in self.remote_systems:
            threading.Thread(target=self.send_to_remote_system, args=(system_address, contents)).start()

    def send_clipboard_file(self):
        if not self.credentials_store:
            messagebox.showerror("Error", "No credentials stored. Please add credentials first.")
            return

        selected_credential_index = self.credentials_combobox.current()
        if selected_credential_index == -1:
            messagebox.showerror("Error", "Please select credentials to use.")
            return

        file_path = self.get_clipboard_file()
        if file_path:
            username, password = self.credentials_store[selected_credential_index]
            for system_address in self.remote_systems:
                threading.Thread(target=self.send_file_to_remote_system, args=(system_address, file_path, username, password)).start()

    def get_clipboard_file(self):
        try:
            import win32clipboard
            win32clipboard.OpenClipboard()
            if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_HDROP):
                file_paths = win32clipboard.GetClipboardData(win32clipboard.CF_HDROP)
                win32clipboard.CloseClipboard()
                if file_paths:
                    return file_paths[0]
            else:
                win32clipboard.CloseClipboard()
                messagebox.showerror("Error", "Clipboard does not contain a valid file format.")
                return None
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get file from clipboard: {e}")
            return None

    def send_file_to_remote_system(self, system_address, file_path, username, password):
        try:
            session = winrm.Session(f'http://{system_address}:5985/wsman', auth=(username, password))
            with open(file_path, 'rb') as f:
                file_content = f.read()
            encoded_content = base64.b64encode(file_content).decode('utf-8')
            desktop_path = f"C:\\Users\\{username}\\Desktop\\{os.path.basename(file_path)}"
            script = f"$content = [System.Convert]::FromBase64String('{encoded_content}'); [System.IO.File]::WriteAllBytes('{desktop_path}', $content)"
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
        contents = pyperclip.paste()
        selected_index = self.remote_systems_list.curselection()
        if selected_index:
            current_system = self.remote_systems_list.get(selected_index)
            self.send_to_remote_system(current_system, contents)
        else:
            messagebox.showinfo("Info", "Please select a system to paste clipboard.")

    def paste_clipboard_all(self):
        self.send_clipboard_contents()

    def report_error(self, message):
        self.after(0, messagebox.showerror, "Error", message)

    def connect_rdp(self):
        selected_index = self.remote_systems_list.curselection()
        if not selected_index:
            messagebox.showinfo("Info", "Please select a system to connect via RDP.")
            return
        system_address = self.remote_systems_list.get(selected_index)
        selected_credential_index = self.credentials_combobox.current()
        if selected_credential_index == -1:
            messagebox.showerror("Error", "Please select credentials to use.")
            return
        username, password = self.credentials_store[selected_credential_index]
        try:
            rdp_file_path = self.create_rdp_file(system_address, username)
            proc = subprocess.Popen(["mstsc", rdp_file_path])
            self.active_sessions[system_address] = proc
            self.session_list.insert(tk.END, f"RDP: {system_address}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not connect to {system_address} via RDP: {e}")

    def create_rdp_file(self, system_address, username):
        rdp_file_content = f"""
        screen mode id:i:2
        use multimon:i:0
        session bpp:i:32
        desktopwidth:i:1920
        desktopheight:i:1080
        compression:i:1
        keyboardhook:i:2
        audiocapturemode:i:0
        videoplaybackmode:i:1
        connection type:i:2
        networkautodetect:i:1
        bandwidthautodetect:i:1
        displayconnectionbar:i:1
        enableworkspacereconnect:i:0
        disable wallpaper:i:0
        allow font smoothing:i:0
        allow desktop composition:i:0
        disable full window drag:i:1
        disable menu anims:i:1
        disable themes:i:0
        disable cursor setting:i:0
        bitmapcachepersistenable:i:1
        full address:s:{system_address}
        username:s:{username}
        prompt for credentials:i:1
        negotiate security layer:i:1
        remoteapplicationmode:i:0
        alternate shell:s:
        shell working directory:s:
        gatewayhostname:s:
        gatewayusagemethod:i:4
        gatewaycredentialssource:i:4
        gatewayprofileusagemethod:i:0
        promptcredentialonce:i:1
        gatewaybrokeringtype:i:0
        use redirection server name:i:0
        rdgiskdcproxy:i:0
        kdcproxyname:s:
        """

        rdp_file_path = os.path.join(os.getenv('TEMP'), f"{system_address}.rdp")
        with open(rdp_file_path, 'w') as rdp_file:
            rdp_file.write(rdp_file_content.strip())
        return rdp_file_path

    def connect_vnc(self):
        selected_index = self.remote_systems_list.curselection()
        if not selected_index:
            messagebox.showinfo("Info", "Please select a system to connect via VNC.")
            return
        system_address = self.remote_systems_list.get(selected_index)
        selected_credential_index = self.credentials_combobox.current()
        if selected_credential_index == -1:
            messagebox.showerror("Error", "Please select credentials to use.")
            return
        username, password = self.credentials_store[selected_credential_index]
        vnc_viewer_path = self.download_vnc_viewer()
        if vnc_viewer_path:
            try:
                proc = subprocess.Popen([vnc_viewer_path, system_address, f"-username={username}", f"-password={password}"])
                self.active_sessions[system_address] = proc
                self.session_list.insert(tk.END, f"VNC: {system_address}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not connect to {system_address} via VNC: {e}")

    def download_vnc_viewer(self):
        vnc_viewer_path = os.path.join(os.getenv('TEMP'), "VNC-Viewer.exe")
        if not os.path.exists(vnc_viewer_path):
            try:
                response = requests.get(VNC_VIEWER_DOWNLOAD_URL)
                with open(vnc_viewer_path, 'wb') as f:
                    f.write(response.content)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to download VNC Viewer: {e}")
                return None
        return vnc_viewer_path

    def bring_session_to_foreground(self, event):
        selected_index = self.session_list.curselection()
        if not selected_index:
            return
        session_name = self.session_list.get(selected_index[0])
        connection_type, system_address = session_name.split(': ')
        if system_address in self.active_sessions:
            proc = self.active_sessions[system_address]
            if proc.poll() is None:
                if connection_type == "RDP":
                    rdp_file_path = self.create_rdp_file(system_address, self.credentials_store[self.credentials_combobox.current()][0])
                    subprocess.run(["mstsc", rdp_file_path])
                elif connection_type == "VNC":
                    vnc_viewer_path = self.download_vnc_viewer()
                    if vnc_viewer_path:
                        subprocess.run([vnc_viewer_path, system_address])
            else:
                messagebox.showerror("Error", f"Session to {system_address} has been closed.")
                self.session_list.delete(selected_index[0])
                del self.active_sessions[system_address]

    def add_credentials(self):
        dialog = CredentialsDialog(self, self.store_credentials)
        dialog.mainloop()

    def store_credentials(self, username, password):
        self.credentials_store.append((username, password))
        self.credentials_list.insert(tk.END, username)
        self.update_credentials_combobox()

    def remove_selected_credential(self):
        selected_indices = self.credentials_list.curselection()
        if not selected_indices:
            messagebox.showinfo("Info", "Please select a credential to remove.")
            return
        for index in selected_indices[::-1]:
            self.credentials_store.pop(index)
            self.credentials_list.delete(index)
        self.update_credentials_combobox()

    def update_credentials_combobox(self):
        self.credentials_combobox['values'] = [cred[0] for cred in self.credentials_store]


if __name__ == "__main__":
    app = ClipboardMultiplexer()
    app.mainloop()
