#!/usr/bin/env python3
"""
Metasploit RPC Connection GUI
=============================

A single-file GUI that:
- Explains how Metasploit RPC connectivity works
- Detects a local Metasploit Framework installation
- Starts msgrpc locally and connects automatically
- Connects to an already-running local or remote RPC service
- Can create an SSH local-forward tunnel to a remote Metasploit RPC listener
- Shows RPC status and Metasploit version
- Does NOT automatically run exploits

Use only with systems and Metasploit instances you own or are authorized to use.

Dependencies:
    python -m pip install requests msgpack

Run:
    python metasploit_connection_gui.py
"""

from __future__ import annotations

import os
import queue
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any

import requests
import msgpack

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
except ImportError:
    raise SystemExit("Tkinter is required to run this GUI.")


APP_TITLE = "Metasploit RPC Connection Manager"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 55552
DEFAULT_USER = "msf"
DEFAULT_URI = "/api/"


class RpcError(RuntimeError):
    pass


@dataclass
class ConnectionSettings:
    host: str
    port: int
    username: str
    password: str
    ssl: bool = False
    uri: str = DEFAULT_URI
    verify_tls: bool = False


class MetasploitRpcClient:
    """
    Minimal Metasploit MessagePack RPC client.

    The RPC request is a MessagePack array:
      ["auth.login", username, password]

    After login:
      ["core.version", token]
    """

    def __init__(self, settings: ConnectionSettings):
        self.settings = settings
        self.token: str | bytes | None = None
        self.session = requests.Session()

    @property
    def endpoint(self) -> str:
        scheme = "https" if self.settings.ssl else "http"
        uri = self.settings.uri
        if not uri.startswith("/"):
            uri = "/" + uri
        return f"{scheme}://{self.settings.host}:{self.settings.port}{uri}"

    def _post(self, payload: list[Any]) -> Any:
        packed = msgpack.packb(payload, use_bin_type=True)
        try:
            response = self.session.post(
                self.endpoint,
                data=packed,
                headers={
                    "Content-Type": "binary/message-pack",
                    "Accept": "binary/message-pack",
                },
                timeout=8,
                verify=self.settings.verify_tls if self.settings.ssl else True,
            )
        except requests.RequestException as exc:
            raise RpcError(f"Unable to reach Metasploit RPC: {exc}") from exc

        if response.status_code >= 400:
            raise RpcError(
                f"RPC server returned HTTP {response.status_code}: "
                f"{response.text[:300]}"
            )

        try:
            return msgpack.unpackb(response.content, raw=False)
        except Exception as exc:
            raise RpcError(
                "The server responded, but the response was not valid "
                "Metasploit MessagePack RPC data."
            ) from exc

    def login(self) -> dict[str, Any]:
        result = self._post(
            ["auth.login", self.settings.username, self.settings.password]
        )
        if not isinstance(result, dict):
            raise RpcError(f"Unexpected login response: {result!r}")

        # Depending on MessagePack decoding/server version, values may be str/bytes.
        status = result.get("result") or result.get(b"result")
        token = result.get("token") or result.get(b"token")

        if isinstance(status, bytes):
            status = status.decode(errors="replace")
        if isinstance(token, bytes):
            token = token.decode(errors="replace")

        if str(status).lower() != "success" or not token:
            raise RpcError(
                "Authentication failed. Check username/password and RPC mode."
            )

        self.token = token
        return result

    def call(self, method: str, *args: Any) -> Any:
        if not self.token:
            raise RpcError("Not authenticated.")
        return self._post([method, self.token, *args])

    def version(self) -> Any:
        return self.call("core.version")

    def logout(self) -> None:
        if not self.token:
            return
        try:
            self.call("auth.logout", self.token)
        except Exception:
            pass
        self.token = None


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1080x760")
        self.root.minsize(920, 650)

        self.events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.rpc_client: MetasploitRpcClient | None = None
        self.msf_process: subprocess.Popen | None = None
        self.ssh_process: subprocess.Popen | None = None

        self.host_var = tk.StringVar(value=DEFAULT_HOST)
        self.port_var = tk.IntVar(value=DEFAULT_PORT)
        self.user_var = tk.StringVar(value=DEFAULT_USER)
        self.pass_var = tk.StringVar()
        self.ssl_var = tk.BooleanVar(value=False)
        self.verify_tls_var = tk.BooleanVar(value=False)
        self.uri_var = tk.StringVar(value=DEFAULT_URI)

        self.ssh_host_var = tk.StringVar()
        self.ssh_user_var = tk.StringVar()
        self.ssh_remote_port_var = tk.IntVar(value=DEFAULT_PORT)
        self.ssh_local_port_var = tk.IntVar(value=DEFAULT_PORT)

        self.status_var = tk.StringVar(value="Not connected")
        self.install_var = tk.StringVar(value="Checking local installation...")

        self._build_ui()
        self.root.after(150, self._process_events)
        self.root.after(250, self.detect_local_metasploit)

    def _build_ui(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        connect_tab = ttk.Frame(notebook)
        guide_tab = ttk.Frame(notebook)
        ssh_tab = ttk.Frame(notebook)
        log_tab = ttk.Frame(notebook)

        notebook.add(connect_tab, text="Connect")
        notebook.add(guide_tab, text="How to Connect")
        notebook.add(ssh_tab, text="SSH Tunnel")
        notebook.add(log_tab, text="Log")

        # ---------------- Connect ----------------
        frame = ttk.Frame(connect_tab, padding=14)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)

        ttk.Label(
            frame,
            text="Metasploit RPC Connection",
            font=("TkDefaultFont", 17, "bold"),
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 14))

        ttk.Label(frame, text="Local Metasploit:").grid(
            row=1, column=0, sticky="w", padx=6, pady=6
        )
        ttk.Label(frame, textvariable=self.install_var).grid(
            row=1, column=1, columnspan=2, sticky="w", padx=6, pady=6
        )

        ttk.Separator(frame).grid(
            row=2, column=0, columnspan=3, sticky="ew", pady=10
        )

        self._entry(frame, 3, "RPC Host", self.host_var)
        self._entry(frame, 4, "RPC Port", self.port_var)
        self._entry(frame, 5, "Username", self.user_var)
        self._entry(frame, 6, "Password", self.pass_var, show="*")
        self._entry(frame, 7, "RPC URI", self.uri_var)

        ttk.Checkbutton(
            frame, text="Use SSL", variable=self.ssl_var
        ).grid(row=8, column=1, sticky="w", padx=6, pady=4)
        ttk.Checkbutton(
            frame,
            text="Verify TLS certificate",
            variable=self.verify_tls_var,
        ).grid(row=9, column=1, sticky="w", padx=6, pady=4)

        ttk.Separator(frame).grid(
            row=10, column=0, columnspan=3, sticky="ew", pady=10
        )

        buttons = ttk.Frame(frame)
        buttons.grid(row=11, column=0, columnspan=3, sticky="ew", pady=8)

        ttk.Button(
            buttons,
            text="Detect Metasploit",
            command=self.detect_local_metasploit,
        ).pack(side="left", padx=4)

        ttk.Button(
            buttons,
            text="Auto Start + Connect",
            command=self.auto_start_and_connect,
        ).pack(side="left", padx=4)

        ttk.Button(
            buttons,
            text="Connect",
            command=self.connect_async,
        ).pack(side="left", padx=4)

        ttk.Button(
            buttons,
            text="Disconnect",
            command=self.disconnect,
        ).pack(side="left", padx=4)

        ttk.Label(
            frame,
            text="Status:",
            font=("TkDefaultFont", 11, "bold"),
        ).grid(row=12, column=0, sticky="w", padx=6, pady=(18, 4))
        ttk.Label(
            frame,
            textvariable=self.status_var,
            font=("TkDefaultFont", 11),
        ).grid(row=12, column=1, sticky="w", padx=6, pady=(18, 4))

        info = (
            "Auto Start + Connect works when Metasploit Framework is installed "
            "on this computer and msfconsole is available. It starts the local "
            "RPC listener on 127.0.0.1 and generates credentials automatically."
        )
        ttk.Label(
            frame,
            text=info,
            wraplength=820,
            justify="left",
        ).grid(row=13, column=0, columnspan=3, sticky="w", padx=6, pady=12)

        # ---------------- Guide ----------------
        guide = tk.Text(guide_tab, wrap="word", padx=16, pady=16)
        guide.pack(fill="both", expand=True)

        guide_text = """HOW CONNECTION WORKS

The Python GUI is a controller. Metasploit Framework remains the security engine.

OPTION 1 — METASPLOIT IS INSTALLED ON THIS COMPUTER

1. Open this program.
2. Click "Auto Start + Connect".
3. The GUI checks for msfconsole.
4. It generates a username/password.
5. It starts Metasploit's msgrpc service on:
       127.0.0.1:55552
6. The GUI waits for the service.
7. It authenticates automatically.
8. The Metasploit version is shown in the Status field.

You do not have to manually type the RPC credentials in this mode.


OPTION 2 — METASPLOIT IS ALREADY RUNNING LOCALLY

Inside msfconsole you can run:

    load msgrpc

Metasploit will display the service address, username and password.

Enter those values in the Connect tab and press "Connect".

Default msgrpc values when no options are supplied are normally:

    Host:       127.0.0.1
    Port:       55552
    Username:   msf
    SSL:        Disabled

The password is normally generated by Metasploit.


OPTION 3 — METASPLOIT IS ON A KALI VM / ANOTHER COMPUTER

On that Metasploit machine, start an RPC service that is reachable by your
client. Prefer a private network/VPN rather than exposing the RPC service to
the public Internet.

Then enter:

    RPC Host:       IP address of the Metasploit machine
    RPC Port:       RPC port
    Username:       RPC username
    Password:       RPC password
    SSL:            Match the server setting

Press "Connect".


OPTION 4 — SSH TUNNEL (RECOMMENDED FOR A REMOTE SERVER)

If SSH access is available, keep Metasploit RPC listening only on its loopback
address and forward it securely:

    Client 127.0.0.1:55552
                |
               SSH
                |
    Remote 127.0.0.1:55552

Use the "SSH Tunnel" tab. The GUI launches your system's ssh command with a
local port-forward. After the tunnel starts, connect to 127.0.0.1 using the
Metasploit RPC credentials.


IF METASPLOIT IS NOT INSTALLED ANYWHERE

The GUI cannot execute Metasploit Framework functionality by itself.
Install Metasploit on this machine, a Kali VM, or another authorized system,
then connect to that instance.


SECURITY NOTES

- Do not expose a Metasploit RPC listener directly to the public Internet.
- Prefer localhost, a private network, VPN, or SSH tunnel.
- Use strong credentials for remotely reachable RPC listeners.
- Only run assessment modules against systems you are authorized to test.
"""
        guide.insert("1.0", guide_text)
        guide.configure(state="disabled")

        # ---------------- SSH ----------------
        ssh = ttk.Frame(ssh_tab, padding=14)
        ssh.pack(fill="both", expand=True)
        ssh.columnconfigure(1, weight=1)

        ttk.Label(
            ssh,
            text="SSH Tunnel to Remote Metasploit",
            font=("TkDefaultFont", 16, "bold"),
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 14))

        self._entry(ssh, 1, "SSH Host", self.ssh_host_var)
        self._entry(ssh, 2, "SSH Username", self.ssh_user_var)
        self._entry(ssh, 3, "Local Forward Port", self.ssh_local_port_var)
        self._entry(ssh, 4, "Remote RPC Port", self.ssh_remote_port_var)

        ttk.Label(
            ssh,
            text=(
                "This assumes Metasploit RPC is listening on 127.0.0.1 on the "
                "remote machine. SSH authentication is handled by your normal "
                "ssh client (key, agent, or terminal prompt)."
            ),
            wraplength=800,
            justify="left",
        ).grid(row=5, column=0, columnspan=3, sticky="w", padx=6, pady=12)

        ssh_buttons = ttk.Frame(ssh)
        ssh_buttons.grid(row=6, column=0, columnspan=3, sticky="w", pady=8)

        ttk.Button(
            ssh_buttons,
            text="Start SSH Tunnel",
            command=self.start_ssh_tunnel,
        ).pack(side="left", padx=4)

        ttk.Button(
            ssh_buttons,
            text="Stop SSH Tunnel",
            command=self.stop_ssh_tunnel,
        ).pack(side="left", padx=4)

        ttk.Button(
            ssh_buttons,
            text="Use Tunnel + Connect",
            command=self.use_tunnel_and_connect,
        ).pack(side="left", padx=4)

        # ---------------- Log ----------------
        self.log_text = tk.Text(log_tab, wrap="word")
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)

    def _entry(self, parent, row, label, var, show=None):
        ttk.Label(parent, text=label).grid(
            row=row, column=0, sticky="w", padx=6, pady=6
        )
        entry = ttk.Entry(parent, textvariable=var, show=show)
        entry.grid(row=row, column=1, sticky="ew", padx=6, pady=6)
        return entry

    def log(self, message: str):
        self.events.put(("log", message))

    def set_status(self, text: str):
        self.events.put(("status", text))

    def _process_events(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    timestamp = time.strftime("%H:%M:%S")
                    self.log_text.insert("end", f"[{timestamp}] {payload}\n")
                    self.log_text.see("end")
                elif kind == "status":
                    self.status_var.set(str(payload))
                elif kind == "message":
                    messagebox.showinfo("Metasploit", str(payload))
                elif kind == "error":
                    messagebox.showerror("Metasploit", str(payload))
        except queue.Empty:
            pass
        self.root.after(150, self._process_events)

    # -----------------------------------------------------
    # Local detection / auto-start
    # -----------------------------------------------------

    def find_msfconsole(self) -> str | None:
        candidates = [
            shutil.which("msfconsole"),
            "/usr/bin/msfconsole",
            "/usr/local/bin/msfconsole",
            "/opt/metasploit-framework/bin/msfconsole",
        ]
        for candidate in candidates:
            if candidate and os.path.exists(candidate):
                return candidate
        return None

    def detect_local_metasploit(self):
        path = self.find_msfconsole()
        if path:
            self.install_var.set(f"Detected: {path}")
            self.log(f"Local Metasploit detected: {path}")
        else:
            self.install_var.set(
                "Not detected — use remote/SSH mode or install Metasploit Framework"
            )
            self.log("Local msfconsole was not found.")

    def auto_start_and_connect(self):
        thread = threading.Thread(
            target=self._auto_start_and_connect_worker,
            daemon=True,
        )
        thread.start()

    def _auto_start_and_connect_worker(self):
        msfconsole = self.find_msfconsole()
        if not msfconsole:
            self.set_status("Metasploit not installed locally")
            self.events.put((
                "error",
                "msfconsole was not found on this computer.\n\n"
                "You can still use this GUI by connecting to Metasploit on "
                "a Kali VM/remote machine, or by using the SSH Tunnel tab."
            ))
            return

        host = "127.0.0.1"
        port = DEFAULT_PORT
        username = DEFAULT_USER
        password = secrets.token_urlsafe(18)

        self.host_var.set(host)
        self.port_var.set(port)
        self.user_var.set(username)
        self.pass_var.set(password)
        self.ssl_var.set(False)
        self.uri_var.set(DEFAULT_URI)

        self.log("Starting local Metasploit RPC service...")
        self.log(f"RPC address: {host}:{port}")
        self.set_status("Starting local Metasploit...")

        # Keep msfconsole alive. The command loads msgrpc and leaves the console
        # process running. We intentionally bind to loopback only.
        load_command = (
            f"load msgrpc "
            f"ServerHost={host} "
            f"ServerPort={port} "
            f"User={username} "
            f"Pass='{password}' "
            f"SSL=false"
        )

        try:
            self.msf_process = subprocess.Popen(
                [msfconsole, "-q", "-x", load_command],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except Exception as exc:
            self.set_status("Failed to start Metasploit")
            self.events.put(("error", f"Could not start msfconsole:\n{exc}"))
            return

        # Read output in another daemon thread so the pipe does not fill.
        threading.Thread(
            target=self._stream_msf_output,
            daemon=True,
        ).start()

        self.log("Waiting for RPC listener...")
        if not self.wait_for_port(host, port, 45):
            self.set_status("RPC service did not start")
            self.events.put((
                "error",
                "Metasploit started, but the RPC port did not become ready.\n\n"
                "Check the Log tab for Metasploit output."
            ))
            return

        self.log("RPC port is reachable. Authenticating...")
        self._connect_worker()

    def _stream_msf_output(self):
        proc = self.msf_process
        if not proc or not proc.stdout:
            return
        try:
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    self.log("msfconsole: " + line)
        except Exception:
            pass

    @staticmethod
    def wait_for_port(host: str, port: int, timeout: int) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection((host, port), timeout=1):
                    return True
            except OSError:
                time.sleep(0.5)
        return False

    # -----------------------------------------------------
    # RPC connection
    # -----------------------------------------------------

    def build_settings(self) -> ConnectionSettings:
        host = self.host_var.get().strip()
        username = self.user_var.get().strip()
        password = self.pass_var.get()

        if not host:
            raise ValueError("RPC host is required.")
        if not username:
            raise ValueError("RPC username is required.")
        if not password:
            raise ValueError("RPC password is required.")

        return ConnectionSettings(
            host=host,
            port=int(self.port_var.get()),
            username=username,
            password=password,
            ssl=bool(self.ssl_var.get()),
            uri=self.uri_var.get().strip() or DEFAULT_URI,
            verify_tls=bool(self.verify_tls_var.get()),
        )

    def connect_async(self):
        threading.Thread(
            target=self._connect_worker,
            daemon=True,
        ).start()

    def _connect_worker(self):
        try:
            settings = self.build_settings()
        except Exception as exc:
            self.events.put(("error", str(exc)))
            return

        self.set_status(f"Connecting to {settings.host}:{settings.port}...")
        self.log(f"Connecting to {settings.host}:{settings.port}")

        client = MetasploitRpcClient(settings)

        try:
            client.login()
            version = client.version()
        except Exception as exc:
            self.rpc_client = None
            self.set_status("Connection failed")
            self.log(f"Connection failed: {exc}")
            self.events.put(("error", str(exc)))
            return

        self.rpc_client = client
        self.log("RPC authentication successful.")
        self.log(f"core.version response: {version!r}")

        display = self.format_version(version)
        self.set_status(f"Connected — {display}")
        self.events.put((
            "message",
            f"Connected successfully.\n\n{display}"
        ))

    @staticmethod
    def format_version(version: Any) -> str:
        if isinstance(version, dict):
            # Common server response fields.
            version_value = (
                version.get("version")
                or version.get(b"version")
                or version.get("ruby")
                or version
            )
            if isinstance(version_value, bytes):
                version_value = version_value.decode(errors="replace")
            return f"Metasploit {version_value}"
        return f"Metasploit {version}"

    def disconnect(self):
        if self.rpc_client:
            try:
                self.rpc_client.logout()
            except Exception:
                pass
        self.rpc_client = None
        self.status_var.set("Not connected")
        self.log("Disconnected from RPC service.")

    # -----------------------------------------------------
    # SSH tunnel
    # -----------------------------------------------------

    def start_ssh_tunnel(self):
        if self.ssh_process and self.ssh_process.poll() is None:
            messagebox.showinfo("SSH Tunnel", "SSH tunnel is already running.")
            return

        ssh = shutil.which("ssh")
        if not ssh:
            messagebox.showerror(
                "SSH Tunnel",
                "The ssh command was not found on this computer."
            )
            return

        remote_host = self.ssh_host_var.get().strip()
        ssh_user = self.ssh_user_var.get().strip()
        local_port = int(self.ssh_local_port_var.get())
        remote_port = int(self.ssh_remote_port_var.get())

        if not remote_host or not ssh_user:
            messagebox.showerror(
                "SSH Tunnel",
                "SSH host and SSH username are required."
            )
            return

        destination = f"{ssh_user}@{remote_host}"
        forward = f"{local_port}:127.0.0.1:{remote_port}"

        cmd = [
            ssh,
            "-N",
            "-L", forward,
            "-o", "ExitOnForwardFailure=yes",
            destination,
        ]

        self.log("Starting SSH tunnel:")
        self.log(" ".join(cmd))

        try:
            # stdin/out are inherited so normal SSH key/passphrase behavior works.
            self.ssh_process = subprocess.Popen(cmd)
        except Exception as exc:
            messagebox.showerror("SSH Tunnel", str(exc))
            return

        self.events.put((
            "message",
            "SSH tunnel process started.\n\n"
            f"Local RPC endpoint: 127.0.0.1:{local_port}\n\n"
            "Complete any SSH authentication requested by your system."
        ))

    def stop_ssh_tunnel(self):
        if self.ssh_process and self.ssh_process.poll() is None:
            self.ssh_process.terminate()
            self.log("SSH tunnel stopped.")
        self.ssh_process = None

    def use_tunnel_and_connect(self):
        self.host_var.set("127.0.0.1")
        self.port_var.set(int(self.ssh_local_port_var.get()))
        self.connect_async()

    def on_close(self):
        try:
            self.disconnect()
        except Exception:
            pass

        if self.ssh_process and self.ssh_process.poll() is None:
            try:
                self.ssh_process.terminate()
            except Exception:
                pass

        if self.msf_process and self.msf_process.poll() is None:
            try:
                self.msf_process.terminate()
            except Exception:
                pass

        self.root.destroy()


def main():
    root = tk.Tk()
    app = App(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
