# 🧘 Packet Monk

![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![License](https://img.shields.io/github/license/yogeshxd/packetmonk)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![Tests](https://img.shields.io/badge/tests-automated-blueviolet)

**Packet Monk** is a remote network testing tool that automates router configuration, packet capture, and protocol analysis via SSH. It is designed to help network engineers, testers, and researchers validate routing protocols like BGP and OSPF in a modular and automated way.

> ⚠️ **Note:** All IP addresses, usernames, and passwords used in this project are **dummy values**. Please update them to match your actual environment.

---

## 🚀 Features

- 🔗 Remote router configuration via SSH  
- 🧪 Automated testing of network protocols (BGP, OSPF, etc.)  
- 📦 Remote live packet capture using `tcpdump`  
- 🔍 Packet analysis using `pyshark`  
- 📄 Detailed logging and test reporting  
- 🧼 Post-test cleanup of router configurations  
- 💡 Highly modular and extensible code structure  

---

## 📋 Prerequisites

Before running Packet Monk, ensure you have the following:

- Python 3.7+
- `pyshark` (requires Wireshark/tshark installed)
- `paramiko` for SSH
- `tcpdump` installed on the remote capture machine
- Access to routers with SSH enabled

Install required Python packages:

```bash
pip install pyshark paramiko
```

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/yogeshxd/packetmonk.git
cd packet-monk
```

Edit the `config.py` file with your actual router and remote host details.

---

## ▶️ Usage

Run the test suite:

```bash
python main.py
```

This will:
- Log the start of the program  
- Run all defined test cases from `test_cases.py`  
- Capture and analyze packets  
- Cleanup routers post-test  
- Log the results and output a test report in `test_report.txt`  

### 🎥 How It Feels Running Packet Monk

![monk gif](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExMzh1Zmt6MzQ4azk4eXh5c2FoaW5ucThwMmU2dGk4MmFrc3M5OGZ6biZlcD12MV9naWZzX3NlYXJjaCZjdD1n/5xtDarzqClAvZivLxh6/giphy.gif)

---

## 🧩 Adding New Test Cases

To add a new test case:

1. Open `test_cases.py`
2. Define a function following this format:

```python
def test5():
    """Your test case description"""
    # Connect to routers
    # Run commands
    # Start capture
    # Analyze packets
    # Return "Success" or a custom error message
```

3. Add your test to the list returned by `get_test_cases()`:

```python
def get_test_cases():
    return [
        (test1, "Success"),
        (test2, "Success"),
        (test3, "Success"),
        (test4, "Success"),
        (test5, "Success"),  # New test
    ]
```

---

## 🌐 Adding New Routers

To add new routers:

1. Open `config.py`
2. Add a new router dictionary:

```python
R6 = {
    "hostname": "10.0.137.XXX",
    "port": 22,
    "username": "cisco",
    "password": "cisco123",
    "commands": []
}
```

The router will be automatically detected by `TestManager` for cleanup if its variable name starts with `"R"` followed by a digit (e.g., `R6`, `R7`).

---

## 🔧 Modularity & Extensibility

**Packet Monk** is built to be modular:

- `packet_capture.py` handles remote packet sniffing  
- `packet_analyzer.py` performs PCAP analysis  
- `ssh_manager.py` manages SSH sessions and command execution  
- `test_cases.py` contains test logic (easily expandable)  
- `test_manager.py` controls test execution and router cleanup  
- `logger.py` provides a unified logging mechanism  

### How to Use the Modularity:

- 🔁 Reuse components like `RemotePacketCapture` or `PacketAnalyzer` in other scripts  
- 🧪 Mix and match routers and commands dynamically  
- 🧩 Easily extend with new protocols or tests without rewriting the core  

---

## 🧘 Zen of Packet Monk

![network gif](https://media.giphy.com/media/BxWTWalKTUAdq/giphy.gif)

---

## 📄 License

GNU General Public License – feel free to fork, extend, and adapt to your use case!

---

Happy debugging 🧘  
— *The Packet Monk*
