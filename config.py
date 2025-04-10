#Remote Capturing
remote_host = "10.0.137.21"                 # Debian machine IP
username = "root"                           # Debian login username
password = "root"                           # Debian login password
remote_interface = "eth1"                   # Interface on Debian used for capturing
remote_output_file = "capture.pcap"         # Where tcpdump will write the capture on Debian
local_output_file = "capture.pcap"          # Local file where you want the capture stored

#Routers
R1 = {
        "hostname": "10.0.137.164",
        "port": 22,
        "username": "cisco",
        "password": "cisco123",
        "commands": []
    }

R2 = {
        "hostname": "10.0.137.205",
        "port": 22,
        "username": "cisco",
        "password": "cisco123",
        "commands": []
    }

R3 = {
        "hostname": "10.0.137.11",
        "port": 22,
        "username": "cisco",
        "password": "cisco123",
        "commands": []
    }

R4 = {
        "hostname": "10.0.137.60",
        "port": 22,
        "username": "cisco",
        "password": "cisco123",
        "commands": []
    }

R5 = {
        "hostname": "10.0.137.166",
        "port": 22,
        "username": "cisco",
        "password": "cisco123",
        "commands": []
    }
