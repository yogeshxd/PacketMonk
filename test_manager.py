from logger import Logger
import config
from ssh_manager import SSHManager

class TestManager:
    def __init__(self):
        self.logger = Logger()
        self.test_cases = []

    def add_test_case(self, test_func, expected_output):
        self.test_cases.append({"func": test_func, "expected": expected_output})

    def run_tests(self):
        for index, test in enumerate(self.test_cases, start=1):
            result = test["func"]()
            passed = result == test["expected"]
            self.logger.log("########################################################################################")
            self.logger.log(f"#################################### Test {test["func"].__name__}: {'PASSED' if passed else 'FAILED'} ####################################")
            self.logger.log("########################################################################################")

            def cleanRouter(credentials):
                command_set = [
                    "enable",
                    "cisco123",
                    "configure terminal",
                    "no router bgp 1000",
                    "no router bgp 2000",
                    "no router bgp 3000",
                    "no router ospf 1",
                    "interface e0/0",
                    "ip ospf priority 1",
                    "no ip address",
                    "shutdown",
                    "exit",
                    "interface e0/1",
                    "ip ospf priority 1",
                    "no ip address",
                    "shutdown",
                    "exit",
                    "interface e0/2",
                    "ip ospf priority 1",
                    "no ip address",
                    "shutdown",
                    "exit",
                    "interface e0/3",
                    "ip ospf priority 1",
                    "no ip address",
                    "shutdown",
                    "exit",
                    "interface e1/0",
                    "ip ospf priority 1",
                    "no ip address",
                    "shutdown",
                    "end",
                    "write memory"
                ]
                ssh = SSHManager(**credentials)
                ssh.connect()
                ssh.execute_commands(command_set)
                ssh.close()

            Routers = [name for name in dir(config) if name.startswith("R") and name[1:].isdigit()]
            self.logger.log("############Performing Router Cleanup#####################")
            for router in Routers:
                router_config = getattr(config, router, None)
                if isinstance(router_config, dict):
                    cleanRouter(router_config)
                else:
                    self.logger.log(f"Skipping {router}: Not a valid dictionary")

            with open("test_report.txt", "a") as file:
                file.write(f"Test {test["func"].__name__}: {'PASSED' if passed else 'FAILED'}\n")
                if not passed:
                    file.write(f"Expected: {test['expected']}, Got: {result}\n")
                file.write("\n")

            if not passed:
                self.logger.log(f"Expected: {test['expected']}, Got: {result}")
