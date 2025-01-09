import os
import socket
import threading
import subprocess
import base64
import ssl
import tkinter as tk
from tkinter import ttk, messagebox, Toplevel, StringVar, BooleanVar, filedialog, simpledialog
import pyperclip
import requests
import winrm
from pyvim.connect import SmartConnect, Disconnect
from pyVmomi import vim
from cryptography.fernet import Fernet

try:
    import win32clipboard
except ImportError:
    win32clipboard = None

PORT = 22
VNC_VIEWER_DOWNLOAD_URL = (
    "https://downloads.realvnc.com/download/file/vnc.files/VNC-Connect-Installer-2.3.0-Windows.exe"
)

def traverse_inventory(entity, vm_names):
    if isinstance(entity, vim.Datacenter):
        traverse_inventory(entity.vmFolder, vm_names)
    elif isinstance(entity, vim.Folder):
        for child in entity.childEntity:
            traverse_inventory(child, vm_names)
    elif isinstance(entity, vim.VirtualApp):
        for child in entity.vm:
            traverse_inventory(child, vm_names)
    elif isinstance(entity, vim.VirtualMachine):
        vm_names.append(entity.name)

def get_all_vm_names(content):
    vm_names = []
    for child_entity in content.rootFolder.childEntity:
        traverse_inventory(child_entity, vm_names)
    return vm_names

class CredentialsDialog(Toplevel):
    def __init__(self, parent, on_store_callback):
        super().__init__(parent)
        self.title("Enter Credentials")
        self.geometry("500x250")
        self.configure(bg='black')
        self.resizable(False, False)
        self.on_store_callback = on_store_callback
        self.username_var = StringVar()
        self.password_var = StringVar()
        self.show_password_var = BooleanVar()
        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self, text="Username:", style='Custom.TLabel').pack(pady=5)
        ttk.Entry(self, textvariable=self.username_var, style='Custom.TEntry').pack(pady=5)
        ttk.Label(self, text="Password:", style='Custom.TLabel').pack(pady=5)
        self.password_entry = ttk.Entry(
            self, textvariable=self.password_var, style='Custom.TEntry', show='*'
        )
        self.password_entry.pack(pady=5)
        ttk.Checkbutton(
            self,
            text="Show Password",
            variable=self.show_password_var,
            style='Custom.TCheckbutton',
            command=self.toggle_password
        ).pack(pady=5)
        f = ttk.Frame(self, style='Custom.TFrame')
        f.pack(pady=10)
        ttk.Button(f, text="Store", command=self.on_store, style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(f, text="Cancel", command=self.on_cancel, style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 5))

    def toggle_password(self):
        if self.show_password_var.get():
            self.password_entry.config(show='')
        else:
            self.password_entry.config(show='*')

    def on_store(self):
        u = self.username_var.get().strip()
        p = self.password_var.get()
        if u and p:
            self.on_store_callback(u, p)
            self.destroy()
        else:
            messagebox.showwarning("Warning", "Please enter both username and password.")

    def on_cancel(self):
        self.destroy()

class VCenterImportDialog(tk.Toplevel):
    def __init__(self, parent, encryption_key, on_import_callback):
        super().__init__(parent)
        self.title("Import from vCenter")
        self.geometry("500x250")
        self.configure(bg='black')
        self.resizable(False, False)
        self.encryption_key = encryption_key
        self.fernet = Fernet(self.encryption_key)
        self.on_import_callback = on_import_callback
        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self, text="vCenter Host/IP:", style='Custom.TLabel').pack(pady=5)
        self.vcenter_host_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.vcenter_host_var, style='Custom.TEntry').pack(pady=5)

        ttk.Label(self, text="Username:", style='Custom.TLabel').pack(pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.username_var, style='Custom.TEntry').pack(pady=5)

        ttk.Label(self, text="Password:", style='Custom.TLabel').pack(pady=5)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(
            self, textvariable=self.password_var, style='Custom.TEntry', show='*'
        )
        self.password_entry.pack(pady=5)

        ttk.Label(self, text="CA Certificate Path (Optional):", style='Custom.TLabel').pack(pady=5)
        self.ca_cert_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.ca_cert_var, style='Custom.TEntry').pack(pady=5)

        frame = ttk.Frame(self, style='Custom.TFrame')
        frame.pack(pady=10)
        ttk.Button(frame, text="Import", command=self.on_import, style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(frame, text="Cancel", command=self.on_cancel, style='Custom.TButton').pack(side=tk.LEFT)

    def on_cancel(self):
        self.destroy()

    def on_import(self):
        host = self.vcenter_host_var.get().strip()
        user = self.username_var.get().strip()
        pwd = self.password_var.get()
        ca_cert_path = self.ca_cert_var.get().strip()
        if not host or not user or not pwd:
            messagebox.showerror("Error", "Please enter the required vCenter host, username, and password.")
            return
        self.do_vcenter_import(host, user, pwd, ca_cert_path)

    def do_vcenter_import(self, host, user, pwd, ca_cert_path):
        enc_user = self.fernet.encrypt(user.encode())
        enc_pwd = self.fernet.encrypt(pwd.encode())
        def worker():
            try:
                if ca_cert_path and os.path.exists(ca_cert_path):
                    context = ssl.create_default_context(cafile=ca_cert_path)
                    context.verify_mode = ssl.CERT_REQUIRED
                else:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                dec_user = self.fernet.decrypt(enc_user).decode()
                dec_pwd = self.fernet.decrypt(enc_pwd).decode()

                si = SmartConnect(
                    host=host,
                    user=dec_user,
                    pwd=dec_pwd,
                    port=443,
                    sslContext=context
                )
                content = si.RetrieveContent()
                vm_list = get_all_vm_names(content)
                Disconnect(si)
                if self.on_import_callback:
                    self.on_import_callback(vm_list)

            except Exception as e:
                tk.messagebox.showerror("Error", f"Could not retrieve VMs from vCenter: {e}")
            finally:
                self.destroy()

        import_thread = threading.Thread(target=worker, daemon=True)
        import_thread.start()

class ClipboardMultiplexer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("cMuX V1.3.0")
        self.geometry("1000x600")
        self.configure(bg='black')
        self.option_add("*Menu.background", "black")
        self.option_add("*Menu.foreground", "#00FF00")
        self.option_add("*Menu.activeBackground", "#2F2F2F")
        self.option_add("*Menu.activeForeground", "#00FF00")
        self.style = self.create_styles()
        self.remote_systems = []
        self.active_sessions = {}
        self.credentials_store = []

        cred_key = os.getenv("CRED_ENCRYPTION_KEY")
        if not cred_key:
            cred_key = Fernet.generate_key()
        self.fernet_credentials = Fernet(cred_key)

        clip_key = os.getenv("CLIPBOARD_ENCRYPTION_KEY")
        if not clip_key:
            clip_key = Fernet.generate_key()
        self.fernet_clipboard = Fernet(clip_key)

        self.create_widgets()

    def create_styles(self):
        s = ttk.Style()
        s.configure('Custom.TFrame', background='black')
        s.configure('Custom.TLabel', background='black', foreground='#00FF00')
        s.configure('Custom.TEntry', fieldbackground='black', foreground='#00FF00')
        s.configure('Custom.TButton', background='black', foreground='#00FF00')
        s.configure('Custom.TMenubutton', background='black', foreground='#00FF00')
        s.configure('Custom.TListbox', background='black', foreground='#00FF00')
        s.configure('Custom.TCheckbutton', background='black', foreground='#00FF00')
        s.configure('Custom.TCombobox', fieldbackground='black', foreground='#00FF00')
        return s

    def create_widgets(self):
        f = ttk.Frame(self, style='Custom.TFrame')
        f.pack(padx=10, pady=10, fill=tk.X)
        ttk.Label(f, text="Add Remote System:", style='Custom.TLabel').pack(side=tk.LEFT, padx=(0, 5))
        self.remote_system_entry = ttk.Entry(f, style='Custom.TEntry')
        self.remote_system_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))
        ttk.Button(f, text="Add", command=self.add_remote_system, style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(f, text="Remove", command=self.remove_selected_system, style='Custom.TButton').pack(side=tk.LEFT)

        f2 = ttk.Frame(self, style='Custom.TFrame')
        f2.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.remote_systems_list = tk.Listbox(f2, selectmode=tk.SINGLE, bg='black', fg='#00FF00')
        self.remote_systems_list.pack(fill=tk.BOTH, expand=True)

        f3 = ttk.Frame(self, style='Custom.TFrame')
        f3.pack(padx=10, pady=10, fill=tk.X)
        ttk.Button(f3, text="Send Clipboard to All", command=self.send_clipboard_contents, style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(f3, text="Send Clipboard File to All", command=self.send_clipboard_file, style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(f3, text="Connect RDP", command=self.connect_rdp, style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(f3, text="Connect VNC", command=self.connect_vnc, style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 5))

        menu_bar = tk.Menu(self, bg='black', fg='#00FF00', tearoff=0)
        self.config(menu=menu_bar)

        clipboard_menu = tk.Menu(menu_bar, bg='black', fg='#00FF00', tearoff=0)
        menu_bar.add_cascade(label="Clipboard", menu=clipboard_menu)
        clipboard_menu.add_command(label="Paste into Current Session", command=self.paste_clipboard_current)
        clipboard_menu.add_command(label="Paste into All Sessions", command=self.paste_clipboard_all)

        import_menu = tk.Menu(menu_bar, bg='black', fg='#00FF00', tearoff=0)
        menu_bar.add_cascade(label="Import", menu=import_menu)
        import_menu.add_command(label="From File...", command=self.import_from_file)
        import_menu.add_command(label="From vCenter...", command=self.import_from_vcenter)

        f4 = ttk.Frame(self, style='Custom.TFrame')
        f4.pack(side=tk.RIGHT, fill=tk.Y, padx=10, pady=10)
        ttk.Label(f4, text="Active Sessions:", style='Custom.TLabel').pack()
        self.session_list = tk.Listbox(f4, selectmode=tk.SINGLE, bg='black', fg='#00FF00')
        self.session_list.pack(fill=tk.BOTH, expand=True)
        self.session_list.bind('<<ListboxSelect>>', self.bring_session_to_foreground)

        f5 = ttk.Frame(self, style='Custom.TFrame')
        f5.pack(padx=10, pady=10, fill=tk.X)
        ttk.Button(f5, text="Add Credentials", command=self.add_credentials, style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(f5, text="Remove Credentials", command=self.remove_selected_credential, style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 5))
        self.credentials_list = tk.Listbox(f5, selectmode=tk.SINGLE, bg='black', fg='#00FF00')
        self.credentials_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))

        ttk.Label(f5, text="Select Credentials:", style='Custom.TLabel').pack(side=tk.LEFT, padx=(5, 5))
        self.selected_credentials = StringVar()
        self.credentials_combobox = ttk.Combobox(
            f5,
            textvariable=self.selected_credentials,
            style='Custom.TCombobox',
            state='readonly'
        )
        self.credentials_combobox.pack(fill=tk.X)

    def import_from_file(self):
        def do_import():
            path = filedialog.askopenfilename(filetypes=[("Text/CSV Files", "*.txt *.csv")])
            if not path:
                return
            try:
                with open(path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                for line in lines:
                    line = line.strip()
                    if line and line not in self.remote_systems:
                        self.remote_systems.append(line)
                        self.remote_systems_list.insert(tk.END, line)
            except Exception as e:
                messagebox.showerror("Error", f"Import from file failed: {e}")
        threading.Thread(target=do_import).start()

    def import_from_vcenter(self):
        def on_import_callback(vm_list):
            for vm in vm_list:
                if vm and vm not in self.remote_systems:
                    self.remote_systems.append(vm)
                    self.remote_systems_list.insert(tk.END, vm)

        dialog = VCenterImportDialog(
            parent=self,
            encryption_key=os.getenv("VCENTER_ENCRYPTION_KEY", Fernet.generate_key()),
            on_import_callback=on_import_callback
        )
        dialog.transient(self)
        dialog.grab_set()
        self.wait_window(dialog)

    def add_remote_system(self):
        a = self.remote_system_entry.get().strip()
        if a and a not in self.remote_systems:
            self.remote_systems.append(a)
            self.remote_systems_list.insert(tk.END, a)
            self.remote_system_entry.delete(0, tk.END)
        else:
            messagebox.showwarning("Warning", "Please enter a valid (new) system address.")

    def remove_selected_system(self):
        i = self.get_selected_index(self.remote_systems_list)
        if i is None:
            messagebox.showinfo("Info", "Please select a system to remove.")
            return
        self.remote_systems.pop(i)
        self.remote_systems_list.delete(i)

    def send_clipboard_contents(self):
        c = pyperclip.paste()
        if not c:
            messagebox.showerror("Error", "Clipboard is empty.")
            return
        for s in self.remote_systems:
            threading.Thread(target=self.send_to_remote_system, args=(s, c)).start()

    def send_to_remote_system(self, addr, data):
        try:
            enc_data = self.fernet_clipboard.encrypt(data.encode())
            with socket.create_connection((addr, PORT), timeout=5) as sock:
                sock.sendall(enc_data)
        except Exception as e:
            self.report_error(f"Could not send data to {addr}: {e}")

    def paste_clipboard_current(self):
        i = self.get_selected_index(self.remote_systems_list)
        if i is None:
            messagebox.showinfo("Info", "Please select a system to paste clipboard.")
            return
        addr = self.remote_systems_list.get(i)
        d = pyperclip.paste()
        threading.Thread(target=self.send_to_remote_system, args=(addr, d)).start()

    def paste_clipboard_all(self):
        self.send_clipboard_contents()

    def send_clipboard_file(self):
        if not self.credentials_store:
            messagebox.showerror("Error", "No credentials stored. Please add credentials first.")
            return
        ci = self.credentials_combobox.current()
        if ci == -1:
            messagebox.showerror("Error", "Please select credentials to use.")
            return
        fp = self.get_clipboard_file()
        if not fp:
            return
        u, p_enc = self.credentials_store[ci]
        p = self.fernet_credentials.decrypt(p_enc).decode()
        for s in self.remote_systems:
            threading.Thread(target=self.send_file_to_remote_system, args=(s, fp, u, p)).start()

    def get_clipboard_file(self):
        if not win32clipboard:
            messagebox.showerror("Error", "pywin32 not installed or not supported. File clipboard unavailable.")
            return None
        try:
            win32clipboard.OpenClipboard()
            if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_HDROP):
                f = win32clipboard.GetClipboardData(win32clipboard.CF_HDROP)
                win32clipboard.CloseClipboard()
                if f:
                    return f[0]
            win32clipboard.CloseClipboard()
            messagebox.showerror("Error", "Clipboard does not contain a valid file format.")
            return None
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get file from clipboard: {e}")
            return None

    def send_file_to_remote_system(self, addr, fp, u, p):
        try:
            s = winrm.Session(f'http://{addr}:5985/wsman', auth=(u, p))
            with open(fp, 'rb') as o:
                c = o.read()
            enc = base64.b64encode(c).decode('utf-8')
            d = f"C:\\Users\\{u}\\Desktop\\{os.path.basename(fp)}"
            sc = f"$content = [System.Convert]::FromBase64String('{enc}'); [System.IO.File]::WriteAllBytes('{d}', $content)"
            s.run_ps(sc)
        except Exception as e:
            self.report_error(f"Could not send file to {addr}: {e}")

    def connect_rdp(self):
        i = self.get_selected_index(self.remote_systems_list)
        if i is None:
            messagebox.showinfo("Info", "Please select a system to connect via RDP.")
            return
        addr = self.remote_systems_list.get(i)
        ci = self.credentials_combobox.current()
        if ci == -1:
            messagebox.showerror("Error", "Please select credentials to use.")
            return
        u, p_enc = self.credentials_store[ci]
        try:
            rdp_file_path = self.create_rdp_file(addr, u)
            proc = subprocess.Popen(["mstsc", rdp_file_path])
            self.active_sessions[addr] = proc
            self.session_list.insert(tk.END, f"RDP: {addr}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not connect to {addr} via RDP: {e}")

    def create_rdp_file(self, addr, u):
        c = f"""
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
full address:s:{addr}
username:s:{u}
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
        r = os.path.join(os.getenv('TEMP'), f"{addr}.rdp")
        with open(r, 'w', encoding='utf-8') as f:
            f.write(c.strip())
        return r

    def connect_vnc(self):
        i = self.get_selected_index(self.remote_systems_list)
        if i is None:
            messagebox.showinfo("Info", "Please select a system to connect via VNC.")
            return
        addr = self.remote_systems_list.get(i)
        ci = self.credentials_combobox.current()
        if ci == -1:
            messagebox.showerror("Error", "Please select credentials to use.")
            return
        u, p_enc = self.credentials_store[ci]
        p = self.fernet_credentials.decrypt(p_enc).decode()
        v = self.download_vnc_viewer()
        if not v:
            return
        try:
            proc = subprocess.Popen([v, addr, f"-username={u}", f"-password={p}"])
            self.active_sessions[addr] = proc
            self.session_list.insert(tk.END, f"VNC: {addr}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not connect to {addr} via VNC: {e}")

    def download_vnc_viewer(self):
        v = os.path.join(os.getenv('TEMP'), "VNC-Viewer.exe")
        if not os.path.exists(v):
            try:
                r = requests.get(VNC_VIEWER_DOWNLOAD_URL, timeout=10)
                r.raise_for_status()
                with open(v, 'wb') as f:
                    f.write(r.content)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to download VNC Viewer: {e}")
                return None
        return v

    def bring_session_to_foreground(self, _):
        i = self.get_selected_index(self.session_list)
        if i is None:
            return
        n = self.session_list.get(i)
        t, addr = n.split(': ', 1)
        if addr not in self.active_sessions:
            messagebox.showerror("Error", f"Session to {addr} not found.")
            self.session_list.delete(i)
            return
        p = self.active_sessions[addr]
        if p.poll() is None:
            if t == "RDP":
                ci = self.credentials_combobox.current()
                if ci == -1:
                    messagebox.showerror("Error", "No credentials selected.")
                    return
                u, _ = self.credentials_store[ci]
                rdp_file_path = self.create_rdp_file(addr, u)
                subprocess.run(["mstsc", rdp_file_path])
            elif t == "VNC":
                v = self.download_vnc_viewer()
                if v:
                    subprocess.run([v, addr])
        else:
            messagebox.showerror("Error", f"Session to {addr} has been closed.")
            self.session_list.delete(i)
            del self.active_sessions[addr]

    def add_credentials(self):
        d = CredentialsDialog(self, self.store_credentials)
        d.transient(self)
        d.grab_set()
        self.wait_window(d)

    def store_credentials(self, u, p):
        p_enc = self.fernet_credentials.encrypt(p.encode())
        self.credentials_store.append((u, p_enc))
        self.credentials_list.insert(tk.END, u)
        self.update_credentials_combobox()

    def remove_selected_credential(self):
        i = self.get_selected_index(self.credentials_list)
        if i is None:
            messagebox.showinfo("Info", "Please select a credential to remove.")
            return
        self.credentials_store.pop(i)
        self.credentials_list.delete(i)
        self.update_credentials_combobox()

    def update_credentials_combobox(self):
        self.credentials_combobox['values'] = [c[0] for c in self.credentials_store]
        if not self.credentials_store:
            self.credentials_combobox.set('')

    def get_selected_index(self, lb):
        s = lb.curselection()
        if not s:
            return None
        return s[0]

    def report_error(self, m):
        self.after(0, messagebox.showerror, "Error", m)

if __name__ == "__main__":
    app = ClipboardMultiplexer()
    app.mainloop()
