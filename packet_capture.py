import time
from logger import Logger
from ssh_manager import SSHManager

class RemotePacketCapture:
    def __init__(self, remote_host, username, password, remote_interface, remote_output_file, local_output_file):
        self.remote_host = remote_host
        self.username = username
        self.password = password
        self.remote_interface = remote_interface
        self.remote_output_file = remote_output_file
        self.local_output_file = local_output_file
        self.logger = Logger()
        self.ssh_manager = SSHManager(
            hostname=self.remote_host,
            port=22,  # Default SSH port
            username=self.username,
            password=self.password,
            commands=[]
        )

    def connect(self):
        """Establish SSH connection using SSHManager."""
        self.logger.log(f"Connecting to remote host {self.remote_host}...")
        self.ssh_manager.connect()

    def start_capture(self):
        """Start tcpdump on the remote Debian machine."""
        self.ssh_manager.execute_commands(["sudo pkill tcpdump"])
        cmd = f"sudo tcpdump -i {self.remote_interface} -w {self.remote_output_file}"
        self.logger.log(f"Starting remote capture with command: {cmd}")
        self.ssh_manager.execute_commands([f"nohup {cmd} > /dev/null 2>&1 &"])
        #self.ssh_manager.execute_commands([cmd])
        self.logger.log("Remote capture started.")

    def stop_capture(self):
        """Stop tcpdump and retrieve the capture file."""
        self.logger.log("Stopping remote capture...")
        self.ssh_manager.execute_commands(["sudo pkill tcpdump"])
        time.sleep(2)  # Give tcpdump time to stop
        self.logger.log("Remote capture stopped.")
        self.retrieve_file()

    def retrieve_file(self):
        """Retrieve the remote pcap file using SFTP."""
        try:
            self.logger.log(f"Retrieving file {self.remote_output_file} to {self.local_output_file}...")
            self.ssh_manager.client.open_sftp().get(self.remote_output_file, self.local_output_file)
            self.logger.log("File retrieved successfully.")
        except Exception as e:
            self.logger.log(f"Error retrieving file: {e}")

    def cleanup(self):
        """Close SSH connection using SSHManager."""
        self.logger.log("Closing SSH connection...")
        self.ssh_manager.execute_commands([f"sudo rm {self.remote_output_file}"])
        self.ssh_manager.close()
        self.logger.log("Connections closed.")