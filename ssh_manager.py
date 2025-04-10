import paramiko
import time
from logger import Logger
import sys
output_dict = {}

class SSHManager:
    def __init__(self, hostname, port, username, password, commands):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.commands = commands
        self.client = None
        self.logger = Logger()

    def connect(self):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.hostname, self.port, self.username, self.password, look_for_keys=False, allow_agent=False)
            self.logger.log(f"Connected to {self.hostname}")
        except Exception as e:
            self.logger.log(f"Error connecting to {self.hostname}: {e}")
            sys.exit()

    def execute_commands(self, commands):
        if not self.client:
            self.logger.log(f"Not connected to {self.hostname}")
            return
        
        shell = self.client.invoke_shell()
        time.sleep(1)

        for command in commands:
            self.logger.log(f"Executing on {self.hostname}: {command}")
            shell.send(command + "\n")
            time.sleep(1)
            output = shell.recv(65535).decode('utf-8')
            self.logger.log(output)
            output_dict[command] = output

    def close(self):
        if self.client:
            self.client.close()
            self.logger.log(f"Connection closed for {self.hostname}")
            return output_dict