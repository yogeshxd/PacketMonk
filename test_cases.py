from ssh_manager import SSHManager
import time
from packet_capture import RemotePacketCapture
from packet_analyzer import PacketAnalyzer
import config

def cprint(msg):
    with open("test_report.txt", "a") as file:
        file.write(str(msg)+"\n")
        print(msg)
        file.close()

################################## Test Case 1 ############################################
def test1():
    """Test BGP Configuration on R1 and R2"""

    def capture(outputfile):
        capture = RemotePacketCapture(config.remote_host, config.username, config.password,
                                  config.remote_interface, config.remote_output_file,
                                  outputfile)
        capture.connect()
        return capture

    def analyze(file):
        analyzer = PacketAnalyzer(file)
        return analyzer.analyze_packets()

    outputfile = "test1.pcap"
    capture(outputfile).start_capture()

    # Credentials and commands for R1
    credentials_R1 = {
        "hostname": "10.0.137.164",
        "port": 22,
        "username": "cisco",
        "password": "cisco123",
        "commands": [
            "enable",
            "cisco123",
            "configure terminal",
            "interface e0/0",
            "ip address 192.168.1.1 255.255.255.0",
            "no shutdown",
            "exit",
            "router bgp 1000",
            "network 192.168.1.0",
            "neighbor 192.168.1.2 remote-as 1000",
            "end",
            "write memory",
        ]
    }

    # Credentials and commands for R2
    credentials_R2 = {
        "hostname": "10.0.137.205",
        "port": 22,
        "username": "cisco",
        "password": "cisco123",
        "commands": [
            "enable",
            "cisco123",
            "configure terminal",
            "interface e0/0",
            "ip address 192.168.1.2 255.255.255.0",
            "no shutdown",
            "exit",
            "router bgp 1000",
            "network 192.168.1.0",
            "neighbor 192.168.1.1 remote-as 1000",
            "end",
            "write memory",
        ]
    }

    # Execute commands on R1
    ssh_r1 = SSHManager(**credentials_R1)
    ssh_r1.connect()
    ssh_r1.execute_commands(credentials_R1["commands"])
    command_outputs_r1 = ssh_r1.close()

    # Execute commands on R2
    ssh_r2 = SSHManager(**credentials_R2)
    ssh_r2.connect()
    ssh_r2.execute_commands(credentials_R2["commands"])
    command_outputs_r2 = ssh_r2.close()

    # Check command execution for errors
    for router, command_outputs in {"R1": command_outputs_r1, "R2": command_outputs_r2}.items():
        for command, output in command_outputs.items():
            if "% Invalid input detected" in output or "Incomplete command" in output:
                result = f"Test Failed: Error in command '{command}' on {router}\nOutput:\n{output}"
                return result

    capture(outputfile).stop_capture()
    capture(outputfile).retrieve_file()
    capture(outputfile).cleanup()

    if not any("192.168.1.4" in s for s in analyze(outputfile)):
        return "Desired packet not found!!"
    else:
        return "Success"

##################################################################################################################

################################## Test Case 2 ###################################################################
def test2():
    """Test OSPF Configuration on R1, R2, R3 and R4"""
    credentials_R1 = {
        "hostname": "10.0.137.205",
        "port": 22,
        "username": "cisco",
        "password": "cisco123",
        "commands": []
    }

    credentials_R2 = {
        "hostname": "10.0.137.11",
        "port": 22,
        "username": "cisco",
        "password": "cisco123",
        "commands": []
    }

    credentials_R3 = {
        "hostname": "10.0.137.60",
        "port": 22,
        "username": "cisco",
        "password": "cisco123",
        "commands": []
    }

    credentials_R4 = {
        "hostname": "10.0.137.164",
        "port": 22,
        "username": "cisco",
        "password": "cisco123",
        "commands": []
    }

    commands = [
        [
            #RUT 1
            "enable",
            "cisco123",
            "configure terminal",
            "interface e0/0",
            "ip address 192.168.1.1 255.255.255.0",
            "ip ospf priority 2",
            "no shutdown",
            "exit",
            "router ospf 1",
            "router-id 1.1.1.1",
            "network 192.168.1.0 0.0.0.255 area 0",
            "end",
            "write memory"
        ],
        [
            #RUT_1 2
            "enable",
            "cisco123",
            "configure terminal",
            "interface e0/0",
            "ip ospf priority 1",
            "end",
            "write memory"
        ],
        [
            #RUT_2 3
            "enable",
            "cisco123",
            "configure terminal",
            "router ospf 1",
            "shutdown",
            "end",
            "write memory"
        ],
        [
            #RUT_3 4
            "enable",
            "cisco123",
            "configure terminal",
            "router ospf 1",
            "no shut",
            "end",
            "write memory"
        ],
        [
            #TR1 5
            "enable",
            "cisco123",
            "configure terminal",
            "interface e0/0",
            "ip address 192.168.1.2 255.255.255.0",
            "no shutdown",
            "exit",
            "router ospf 1",
            "router-id 2.2.2.2",
            "network 192.168.1.0 0.0.0.255 area 0",
            "end",
            "write memory"
        ],
        [
            #TR1_1 6
            "enable",
            "cisco123",
            "configure terminal",
            "router ospf 1",
            "shutdown",
            "end",
            "write memory"
        ],
        [
            #TRI1_2 7
            "enable",
            "cisco123",
            "configure terminal",
            "router ospf 1",
            "no shut",
            "end",
            "write memory"
        ],
        [
            #TR2 8
            "enable",
            "cisco123",
            "configure terminal",
            "interface e0/0",
            "ip address 192.168.1.3 255.255.255.0",
            "no shutdown",
            "exit",
            "router ospf 1",
            "router-id 3.3.3.3",
            "network 192.168.1.0 0.0.0.255 area 0",
            "end",
            "write memory"
        ],
        [
            #TR2_1 9
            "enable",
            "cisco123",
            "configure terminal",
            "router ospf 1",
            "no shut",
            "end",
            "write memory"
        ],
        [
            #TR2_2 10
            "enable",
            "cisco123",
            "configure terminal",
            "router ospf 1",
            "no shut",
            "end",
            "write memory"
        ],
        [
            #TR3 11
            "enable",
            "cisco123",
            "configure terminal",
            "interface e0/0",
            "ip address 192.168.1.4 255.255.255.0",
            "no shutdown",
            "exit",
            "router ospf 1",
            "router-id 4.4.4.4",
            "network 192.168.1.0 0.0.0.255 area 0",
            "end",
            "write memory"
        ],
        [
            #TR3_1 12
            "enable",
            "cisco123",
            "configure terminal",
            "interface e0/0",
            "ip ospf priority 2",
            "end",
            "write memory"
        ],
        [
            #tr3_2 13
            "enable",
            "cisco123",
            "configure terminal",
            "router ospf 1",
            "shutdown",
            "end",
            "write memory"
        ],
        [
            #TR3_3 14
            "enable",
            "cisco123",
            "configure terminal",
            "router ospf 1",
            "no shut",
            "end",
            "write memory"
        ]
    ]

    def run(credentials, command_set):
        ssh = SSHManager(**credentials)
        ssh.connect()
        ssh.execute_commands(command_set)
        command_outputs= ssh.close()
        return command_outputs


    # Check command execution for errors
    def check(router, outputs):
        for command, output in outputs.items():
            if "% Invalid input detected" in output or "Incomplete command" in output:
                result = f"Test Failed: Error in command '{command}' on {router}\nOutput:\n{output}"
                return result
        return "Success"

    def capture(outputfile):
        capture = RemotePacketCapture(config.remote_host, config.username, config.password,
                                  config.remote_interface, config.remote_output_file,
                                  outputfile)
        capture.connect()
        return capture

    def analyze(file):
        analyzer = PacketAnalyzer(file)
        return analyzer.analyze_packets()

    set_1 = [
        ["R1", credentials_R1, commands[4]]
    ]

    set_2 = [
        ["R2", credentials_R2, commands[7]]
    ]

    set_3 = [
        ["R3", credentials_R3, commands[10]],
        ["R4", credentials_R4, commands[0]],
        ["R1", credentials_R1, commands[5]]
    ]

    set_4 = [
        ["R4", credentials_R4, commands[1]],
        ["R3", credentials_R3, commands[11]],
        ["R4", credentials_R4, commands[2]],
        ["R3", credentials_R3, commands[12]],
        ["R2", credentials_R2, commands[8]],
        ["R1", credentials_R1, commands[6]]
    ]

    set_5 = [
        ["R2", credentials_R2, commands[9]]
    ]

    set_6 = [
        ["R3", credentials_R3, commands[13]],
        ["R4", credentials_R4, commands[3]],
        ["R1", credentials_R1, commands[5]]
    ]

    def com(sets):
        for _ in sets:
            outputs = run(_[1], _[2])
            result = check(_[0], outputs)
            if result != "Success":
                return result
        return "Success"

    #Part A
    outputfile = "test2_partA.pcap"
    capture(outputfile).start_capture()

    result = com(set_1)
    if result != "Success":
        return result
    time.sleep(50)

    result = com(set_2)
    if result != "Success":
        return result
    time.sleep(30)

    result = com(set_3)
    if result != "Success":
        return result
    time.sleep(40)

    capture(outputfile).stop_capture()
    capture(outputfile).retrieve_file()
    capture(outputfile).cleanup()

    if not any("192.168.1.4" in s for s in analyze(outputfile)):
        return "Desired packet not found!!"

    #Part B
    outputfile = "test2_partB.pcap"
    capture(outputfile).start_capture()

    result = com(set_4)
    if result != "Success":
        return result
    time.sleep(50)

    result = com(set_5)
    if result != "Success":
        return result
    time.sleep(30)

    result = com(set_6)
    if result != "Success":
        return result
    time.sleep(40)

    capture(outputfile).stop_capture()
    capture(outputfile).retrieve_file()
    capture(outputfile).cleanup()

    if not any("192.168.1.4" in s for s in analyze(outputfile)):
        return "Desired packet not found!!"
    else:
        return "Success"

##################################################################################################################

################################## Test Case 3 ###################################################################

def test3():
    """Test OSPF Configuration on R1, R2, R3 and R4"""
    credentials_R1 = {
        "hostname": "10.0.137.164",
        "port": 22,
        "username": "cisco",
        "password": "cisco123",
        "commands": []
    }

    credentials_R2 = {
        "hostname": "10.0.137.205",
        "port": 22,
        "username": "cisco",
        "password": "cisco123",
        "commands": []
    }

    credentials_R3 = {
        "hostname": "10.0.137.11",
        "port": 22,
        "username": "cisco",
        "password": "cisco123",
        "commands": []
    }

    commands = [
        [
            # TR1 0
            "enable",
            "cisco123",
            "configure terminal",
            "interface e0/0",
            "ip address 192.168.1.1 255.255.255.0",
            "no shutdown",
            "exit",
            "interface e1/0",
            "ip address 192.168.3.1 255.255.255.0",
            "no shutdown",
            "exit",
            "router bgp 1000",
            "network 192.168.1.0",
            "neighbor 192.168.1.2 remote-as 2000",
            "end",
            "write memory"
        ],
        [
            #TR1_1 1
            "enable",
            "cisco123",
            "configure terminal",
            "router bgp 1000",
            "network 192.168.3.0",
            "end",
            "write memory"
        ],
        [
            #RUT 2
            "enable",
            "cisco123",
            "configure terminal",
            "interface e0/0",
            "ip address 192.168.1.2 255.255.255.0",
            "no shutdown",
            "exit",
            "interface e0/1",
            "ip address 192.168.2.1 255.255.255.0",
            "no shutdown",
            "exit",
            "interface e1/0",
            "ip address 192.168.4.1 255.255.255.0",
            "no shutdown",
            "exit",
            "router bgp 2000",
            "network 192.168.1.0",
            "neighbor 192.168.1.1 remote-as 1000",
            "network 192.168.2.0",
            "neighbor 192.168.2.2 remote-as 2000",
            "end",
            "write memory"
        ],
        [
            #RUT_1 3
            "enable",
            "cisco123",
            "configure terminal",
            "router bgp 2000",
            "network 192.168.4.0",
            "end",
            "write memory"
        ],
        [
            #RUT_2 4
            "enable",
            "cisco123",
            "configure terminal",
            "router bgp 2000",
            "no neighbor 192.168.2.2 remote-as 2000",
            "neighbor 192.168.2.2 remote-as 3000",
            "end",
            "write memory"
        ],
        [
            #TR2 5
            "enable",
            "cisco123",
            "configure terminal",
            "interface e0/1",
            "ip address 192.168.2.2 255.255.255.0",
            "no shutdown",
            "exit",
            "interface e1/0",
            "ip address 192.168.5.1 255.255.255.0",
            "no shutdown",
            "exit",
            "router bgp 2000",
            "network 192.168.2.0",
            "neighbor 192.168.2.1 remote-as 2000",
            "end",
            "write memory"
        ],
        [
            #TR2_1 6
            "enable",
            "cisco123",
            "configure terminal",
            "router bgp 2000",
            "network 192.168.5.0",
            "end",
            "write memory"
        ],
        [
            #TR2_2 7
            "enable",
            "cisco123",
            "configure terminal",
            "no router bgp 2000",
            "router bgp 3000",
            "network 192.168.2.0",
            "neighbor 192.168.2.1 remote-as 2000",
            "end",
            "write memory"
        ],
        [
            #TR2_3 8
            "enable",
            "cisco123",
            "configure terminal",
            "router bgp 3000",
            "network 192.168.5.0",
            "end",
            "write memory"
        ]
    ]

    def run(credentials, command_set):
        ssh = SSHManager(**credentials)
        ssh.connect()
        ssh.execute_commands(command_set)
        command_outputs= ssh.close()
        return command_outputs


    # Check command execution for errors
    def check(router, outputs):
        for command, output in outputs.items():
            if "% Invalid input detected" in output or "Incomplete command" in output:
                result = f"Test Failed: Error in command '{command}' on {router}\nOutput:\n{output}"
                return result
        return "Success"

    def capture(outputfile):
        capture = RemotePacketCapture(config.remote_host, config.username, config.password,
                                  config.remote_interface, config.remote_output_file,
                                  outputfile)
        capture.connect()
        return capture

    def analyze(file):
        analyzer = PacketAnalyzer(file)
        return analyzer.analyze_packets()

    set_1 = [
        ["R1", credentials_R1, commands[0]],
        ["R2", credentials_R2, commands[2]],
        ["R3", credentials_R3, commands[5]]
    ]

    set_2 = [
        ["R2", credentials_R2, commands[3]]
    ]

    set_3 = [
        ["R1", credentials_R1, commands[1]]
    ]

    set_4 = [
        ["R3", credentials_R3, commands[6]]
    ]

    set_5 = [
        ["R2", credentials_R2, commands[4]],
        ["R3", credentials_R3, commands[7]]
    ]

    set_6 = [
        ["R3", credentials_R3, commands[8]]
    ]

    def com(combinations):
        for _ in combinations:
            outputs = run(_[1], _[2])
            result = check(_[0], outputs)
            if result != "Success":
                return result
        return "Success"

    outputfile = "test3.pcap"
    capture(outputfile).start_capture()

    result = com(set_1)
    if result != "Success":
        return result
    time.sleep(30)

    result = com(set_2)
    if result != "Success":
        return result
    time.sleep(20)

    result = com(set_3)
    if result != "Success":
        return result
    time.sleep(20)

    result = com(set_4)
    if result != "Success":
        return result
    time.sleep(20)

    result = com(set_5)
    if result != "Success":
        return result
    time.sleep(20)

    result = com(set_6)
    if result != "Success":
        return result

    capture(outputfile).stop_capture()
    capture(outputfile).retrieve_file()
    capture(outputfile).cleanup()

    if not any("192.168.1.4" in s for s in analyze(outputfile)):
        return "Desired packet not found!!"
    else:
        return "Success"

##################################################################################################################

################################## Test Case 4 ###################################################################
def test4():
    """Test OSPF Configuration on R1, R2, R3 and R4"""
    credentials_R1 = {
        "hostname": "10.0.137.205",
        "port": 22,
        "username": "cisco",
        "password": "cisco123",
        "commands": []
    }

    credentials_R2 = {
        "hostname": "10.0.137.11",
        "port": 22,
        "username": "cisco",
        "password": "cisco123",
        "commands": []
    }

    credentials_R3 = {
        "hostname": "10.0.137.60",
        "port": 22,
        "username": "cisco",
        "password": "cisco123",
        "commands": []
    }

    credentials_R4 = {
        "hostname": "10.0.137.164",
        "port": 22,
        "username": "cisco",
        "password": "cisco123",
        "commands": []
    }

    commands = [
        [
            #RUT 0
            "enable",
            "cisco123",
            "configure terminal",
            "interface e0/0",
            "ip address 192.168.1.1 255.255.255.0",
            "no shutdown",
            "exit",
            "router ospf 1",
            "router-id 1.1.1.1",
            "network 192.168.1.0 0.0.0.255 area 0",
            "end",
            "write memory"
        ],
        [
            #RUT_1 1
            "enable",
            "cisco123",
            "configure terminal",
            "router ospf 1",
            "shutdown",
            "end",
            "write memory"
        ],
        [
            #RUT_2 2
            "enable",
            "cisco123",
            "configure terminal",
            "router ospf 1",
            "no shut",
            "end",
            "write memory"
        ],
        [
            #TR1 3
            "enable",
            "cisco123",
            "configure terminal",
            "interface e0/0",
            "ip address 192.168.1.2 255.255.255.0",
            "no shutdown",
            "exit",
            "router ospf 1",
            "router-id 2.2.2.2",
            "network 192.168.1.0 0.0.0.255 area 0",
            "end",
            "write memory"
        ],
        [
            #TR1_1 4
            "enable",
            "cisco123",
            "configure terminal",
            "router ospf 1",
            "shutdown",
            "end",
            "write memory"
        ],
        [
            #TR1_2 5
            "enable",
            "cisco123",
            "configure terminal",
            "router ospf 1",
            "no shut",
            "end",
            "write memory"
        ],
        [
            #TR2 6
            "enable",
            "cisco123",
            "configure terminal",
            "interface e0/0",
            "ip address 192.168.1.3 255.255.255.0",
            "no shutdown",
            "exit",
            "router ospf 1",
            "router-id 3.3.3.3",
            "network 192.168.1.0 0.0.0.255 area 0",
            "end",
            "write memory"
        ],
        [
            #TR2_1 7
            "enable",
            "cisco123",
            "configure terminal",
            "router ospf 1",
            "shutdown",
            "end",
            "write memory"
        ],
        [
            #TR2_2 8
            "enable",
            "cisco123",
            "configure terminal",
            "router ospf 1",
            "no shut",
            "end",
            "write memory"
        ],
        [
            #TR3 9
            "enable",
            "cisco123",
            "configure terminal",
            "interface e0/0",
            "ip address 192.168.1.4 255.255.255.0",
            "no shutdown",
            "exit",
            "router ospf 1",
            "router-id 4.4.4.4",
            "network 192.168.1.0 0.0.0.255 area 0",
            "end",
            "write memory"
        ],
        [
            #TR3_1 10
            "enable",
            "cisco123",
            "configure terminal",
            "router ospf 1",
            "shutdown",
            "end",
            "write memory"
        ],
        [
            #TR3_2 11
            "enable",
            "cisco123",
            "configure terminal",
            "router ospf 1",
            "no shut",
            "end",
            "write memory"
        ]
    ]

    def run(credentials, command_set):
        ssh = SSHManager(**credentials)
        ssh.connect()
        ssh.execute_commands(command_set)
        command_outputs= ssh.close()
        return command_outputs


    # Check command execution for errors or outputs
    def check(router, outputs):
        for command, output in outputs.items():
            if "% Invalid input detected" in output or "Incomplete command" in output:
                result = f"Test Failed: Error in command '{command}' on {router}\nOutput:\n{output}"
                return result
        return "Success"

    def capture(outputfile):
        capture = RemotePacketCapture(config.remote_host, config.username, config.password,
                                  config.remote_interface, config.remote_output_file,
                                  outputfile)
        capture.connect()
        return capture

    def analyze(file):
        analyzer = PacketAnalyzer(file)
        return analyzer.analyze_packets()

    set_1 = [
        ["R1", credentials_R1, commands[3]]
    ]

    set_2 = [
        ["R2", credentials_R2, commands[6]]
    ]

    set_3 = [
        ["R3", credentials_R3, commands[9]]
    ]

    set_4 = [
        ["R4", credentials_R4, commands[0]]
    ]

    set_5 = [
        ["R1", credentials_R1, commands[4]],
        ["R2", credentials_R2, commands[7]],
        ["R3", credentials_R3, commands[10]],
        ["R4", credentials_R4, commands[1]],
        ["R1", credentials_R1, commands[5]]
    ]

    set_6 = [
        ["R4", credentials_R4, commands[2]]
    ]

    set_7 = [
        ["R2", credentials_R2, commands[8]]
    ]

    set_8 = [
        ["R3", credentials_R3, commands[11]]
    ]

    set_9 = [
        ["R1", credentials_R1, commands[4]],
        ["R2", credentials_R2, commands[7]],
        ["R3", credentials_R3, commands[10]],
        ["R4", credentials_R4, commands[1]],
        ["R4", credentials_R4, commands[2]]
    ]

    set_10 = [
        ["R1", credentials_R1, commands[5]]
    ]

    set_11 = [
        ["R2", credentials_R2, commands[8]]
    ]

    set_12 = [
        ["R3", credentials_R3, commands[11]]
    ]

    def com(combinations):
        for _ in combinations:
            outputs = run(_[1], _[2])
            result = check(_[0], outputs)
            if result != "Success":
                return result
        return "Success"

    #Part A
    outputfile = "test4_partA.pcap"
    capture(outputfile).start_capture()

    result = com(set_1)
    if result != "Success":
        return result
    time.sleep(50)

    result = com(set_2)
    if result != "Success":
        return result
    time.sleep(30)

    result = com(set_3)
    if result != "Success":
        return result
    time.sleep(30)

    result = com(set_4)
    if result != "Success":
        return result
    time.sleep(30)

    capture(outputfile).stop_capture()
    capture(outputfile).retrieve_file()
    capture(outputfile).cleanup()

    if not any("192.168.1.4" in s for s in analyze(outputfile)):
        return "Desired packet not found!!"

    #Part B
    outputfile = "test4_partB.pcap"
    capture(outputfile).start_capture()

    result = com(set_5)
    if result != "Success":
        return result
    time.sleep(50)

    result = com(set_6)
    if result != "Success":
        return result
    time.sleep(30)

    result = com(set_7)
    if result != "Success":
        return result
    time.sleep(30)

    result = com(set_8)
    if result != "Success":
        return result
    time.sleep(30)

    capture(outputfile).stop_capture()
    capture(outputfile).retrieve_file()
    capture(outputfile).cleanup()

    if not any("192.168.1.4" in s for s in analyze(outputfile)):
        return "Desired packet not found!!"

    #Part C
    outputfile = "test4_partC.pcap"
    capture(outputfile).start_capture()

    result = com(set_9)
    if result != "Success":
        return result
    time.sleep(50)

    result = com(set_10)
    if result != "Success":
        return result
    time.sleep(30)

    result = com(set_11)
    if result != "Success":
        return result
    time.sleep(30)

    result = com(set_12)
    if result != "Success":
        return result
    time.sleep(30)

    capture(outputfile).stop_capture()
    capture(outputfile).retrieve_file()
    capture(outputfile).cleanup()

    if not any("192.168.1.4" in s for s in analyze(outputfile)):
        return "Desired packet not found!!"
    else:
        return "Success"

##################################################################################################################

#driver_code
def get_test_cases():
    """Return test cases with expected outputs."""
    return [
        (test1, "Success"),
        (test2, "Success"),
        (test3, "Success"),
        (test4, "Success"),
    ]
