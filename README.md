
# Metasploit RPC GUI

A Python-based graphical interface for connecting to and managing Metasploit Framework through its RPC API.

The project is designed to simplify Metasploit RPC connectivity by providing a GUI for local, remote, and SSH-tunneled connections. It can automatically detect a local Metasploit installation, start the RPC service, generate credentials, authenticate, and verify the connection.

> This project is intended only for authorized security testing, cybersecurity labs, and educational use.

## Features

* Graphical interface built with Python Tkinter
* Detects local Metasploit Framework installations
* Automatically starts `msfconsole`
* Automatically starts the `msgrpc` RPC service
* Generates RPC credentials automatically
* Connects to local Metasploit instances
* Connects to remote Metasploit instances
* SSH tunnel support for remote RPC connections
* Configurable RPC host and port
* Username and password authentication
* SSL support
* RPC connection testing
* Displays Metasploit version after successful connection
* Live connection and Metasploit logs
* Built-in “How to Connect” guide
* Single Python file architecture

## Project Architecture

```text
                User
                 │
                 ▼
       ┌─────────────────────┐
       │ Python Tkinter GUI  │
       └──────────┬──────────┘
                  │
         Connection Manager
                  │
       ┌──────────┼───────────┐
       │          │           │
       ▼          ▼           ▼
    Local       Remote     SSH Tunnel
 Metasploit   Metasploit       │
       │          │             │
       └──────────┴─────────────┘
                  │
                  ▼
          Metasploit RPC API
                  │
                  ▼
        Metasploit Framework
```

## Connection Modes

### 1. Automatic Local Connection

If Metasploit Framework is installed on the same computer, the application can automatically:

1. Detect `msfconsole`
2. Generate RPC credentials
3. Start Metasploit
4. Load the `msgrpc` plugin
5. Start the RPC listener
6. Wait for the service
7. Authenticate automatically
8. Display the Metasploit version

Use:

```text
Auto Start + Connect
```

from the GUI.

---

### 2. Manual Local Connection

Start Metasploit:

```bash
msfconsole
```

Inside Metasploit:

```text
load msgrpc
```

Enter the RPC credentials shown by Metasploit into the GUI.

Typical RPC configuration:

```text
Host: 127.0.0.1
Port: 55552
Username: msf
Password: generated password
```

---

### 3. Remote Metasploit Connection

Metasploit may also run on another authorized machine such as:

* Kali Linux VM
* Linux server
* Cybersecurity laboratory system
* Remote penetration-testing environment

Enter the RPC server address and credentials into the GUI and press:

```text
Connect
```

---

### 4. SSH Tunnel

The application can create an SSH port-forward to a remote Metasploit server.

Architecture:

```text
Python GUI
    │
127.0.0.1:55552
    │
    ▼
SSH Tunnel
    │
    ▼
Remote Kali Linux
    │
127.0.0.1:55552
    │
    ▼
Metasploit RPC
```

This allows the Metasploit RPC service to remain bound to localhost on the remote system.

## Requirements

* Python 3
* Metasploit Framework for full functionality
* Tkinter
* Requests
* MessagePack

Install Python dependencies:

```bash
python -m pip install requests msgpack
```

## Running the Application

Clone the repository:

```bash
git clone https://github.com/yourusername/metasploit-rpc-gui.git
```

Enter the project directory:

```bash
cd metasploit-rpc-gui
```

Run:

```bash
python metasploit_connection_gui.py
```

On some Linux systems:

```bash
python3 metasploit_connection_gui.py
```

## Project Structure

```text
metasploit-rpc-gui/
│
├── metasploit_connection_gui.py
├── README.md
├── requirements.txt
├── LICENSE
└── screenshots/
```

## Technologies Used

* Python
* Tkinter
* Metasploit Framework
* Metasploit MessagePack RPC API
* Requests
* MessagePack
* SSH

## Current Capabilities

The current version focuses on Metasploit RPC connection management.

It supports:

* RPC service discovery
* RPC authentication
* Automatic local startup
* Remote RPC connectivity
* SSH tunneling
* Metasploit version verification
* Connection status monitoring

## Planned Features

Future versions may include:

* Metasploit module browser
* Auxiliary/scanner module management
* Module search
* Module information viewer
* Required-option configuration
* Job monitoring
* Session inventory
* Authorized assessment workflows
* Vulnerability findings dashboard
* CVE references
* JSON reporting
* HTML reporting
* PDF reporting
* CSV reporting
* Integration with the OWASP + Burp automation framework

## Use Cases

This project can be used for:

* Cybersecurity education
* Ethical hacking laboratories
* Penetration-testing labs
* Metasploit RPC research
* Security automation research
* Python cybersecurity projects
* Learning security-tool API integration

## Security Notice

This application does not replace Metasploit Framework.

It acts as a graphical RPC client and automation controller for an existing Metasploit installation.

Do not expose the Metasploit RPC service directly to the public Internet.

Prefer:

* localhost
* private networks
* VPN
* SSH tunneling

Only use Metasploit against systems that you own or have explicit authorization to test.

## Disclaimer

This project is intended for educational purposes and authorized security testing only.

The developer is not responsible for misuse of this software.

Users are responsible for ensuring that all testing is performed with appropriate authorization and in accordance with applicable laws and policies.

## Author

**Abhishek Rahang**

Cybersecurity / Cloud Technology / Information Security

## License

This project can be released under the MIT License.
