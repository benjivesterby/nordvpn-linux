import contextlib
import os
import re

import requests
import subprocess
import time
from enum import Enum

import pytest
import sh
from lib.shell import sh_no_tty
from lib import network

from . import daemon, info, logging, login, ssh

PEER_USERNAME = login.get_credentials("qa-peer").email
LOCAL_TOKEN = login.get_credentials("default").token
PEER_TOKEN = login.get_credentials("qa-peer").token
BASE_API = "https://api.nordvpn.com/v1"

TELIO_EXPECTED_RELAY_TO_DIRECT_TIME = 5.0
TELIO_EXPECTED_RTT = 5.0
TELIO_EXPECTED_PACKET_LOSS = 0.0

LANS = [
    "169.254.0.0/16",
    "192.168.0.0/16",
    "172.16.0.0/12",
    "10.0.0.0/8",
]

strip_colors = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', flags=re.IGNORECASE)


class TestUtils:
    @staticmethod
    def setup_module(ssh_client: ssh.Ssh):
        os.makedirs("/home/qa/.config/nordvpn", exist_ok=True)
        os.makedirs("/home/qa/.cache/nordvpn", exist_ok=True)
        ssh_client.connect()
        daemon.install_peer(ssh_client)
        TestUtils.allowlist_ssh(ssh_client, network.FWMARK)


    @staticmethod
    def teardown_module(ssh_client: ssh.Ssh):
        # Preserve other peer log
        dest_logs_path = f"{os.environ['WORKDIR']}/dist/logs"
        ssh_client.download_file("/var/log/nordvpn/daemon.log", f"{dest_logs_path}/other-peer-daemon.log")
        daemon.uninstall_peer(ssh_client)
        ssh_client.disconnect()


    @staticmethod
    def setup_function(ssh_client: ssh.Ssh):
        logging.log()

        delete_machines_by_identifier(token=LOCAL_TOKEN)
        delete_machines_by_identifier(token=PEER_TOKEN)

        # if setup_function fails, teardown won't be executed, so daemon is not stopped
        if daemon.is_running():
            daemon.stop()

        daemon.start()
        daemon.start_peer(ssh_client)
        login.login_as("default")
        login.login_as("qa-peer", ssh_client)
        sh_no_tty.nordvpn.set.meshnet.on()
        ssh_client.exec_command("nordvpn set mesh on")
        revoke_all_invites()
        revoke_all_invites_in_peer(ssh_client)
        add_peer(ssh_client)


    @staticmethod
    def teardown_function(ssh_client: ssh.Ssh):
        logging.log(data=info.collect())
        logging.log()
        ssh_client.exec_command("nordvpn set defaults --logout --off-killswitch")
        sh_no_tty.nordvpn.set.defaults("--logout", "--off-killswitch")
        daemon.stop_peer(ssh_client)
        daemon.stop()
        sh_no_tty.sudo.iptables("-F")
        ssh_client.exec_command("sudo iptables -F")


    @staticmethod
    def allowlist_ssh(ssh_client: ssh.Ssh, fwmark: int):
        for rules in TestUtils.ssh_allowlist_rule_args(True, fwmark):
            ssh_client.exec_command(f"sudo iptables -t mangle -A {' '.join(rules)}")
        for rules in TestUtils.ssh_allowlist_rule_args(False, fwmark):
            sh_no_tty.sudo.iptables("-t", "mangle", "-A", *rules)

    @staticmethod
    def ssh_allowlist_rule_args(incoming: bool, fwmark: int) -> list[list[str]]:
        prerouting_port_arg = "--dport" if incoming else "--sport"
        output_port_arg = "--sport" if incoming else "--dport"
        return [
                ["PREROUTING", "-p", "tcp", prerouting_port_arg, "22", "-j", "CONNMARK", "--set-xmark", str(fwmark)],
                ["OUTPUT", "-p", "tcp", output_port_arg, "22", "-j", "MARK", "--set-xmark", str(fwmark)],
        ]

class PeerName(Enum):
    Hostname = 0
    Ip = 1
    Pubkey = 2
    Nickname = 3


class Peer:
    @staticmethod
    def _convert_to_bool(value):
        return value.lower() == "enabled" if value is not None else None

    def __init__(
            self,
            hostname: str,
            nickname: str,
            ip: str,
            public_key: str,
            os: str,
            distribution: str,
            status: str | None = None,
            allow_incoming_traffic: bool | None = None,
            allow_routing: bool | None = None,
            allow_lan_access: bool | None = None,
            allow_sending_files: bool | None = None,
            allows_incoming_traffic: bool | None = None,
            allows_routing: bool | None = None,
            allows_lan_access: bool | None = None,
            allows_sending_files: bool | None = None,
            accept_fileshare_automatically: bool | None = None
            ):
        self.hostname = hostname
        self.nickname = nickname
        self.status = status
        self.ip = ip
        self.public_key = public_key
        self.os = os
        self.distribution = distribution
        self.allow_incoming_traffic = self._convert_to_bool(allow_incoming_traffic)
        self.allow_routing = self._convert_to_bool(allow_routing)
        self.allow_lan_access = self._convert_to_bool(allow_lan_access)
        self.allow_sending_files = self._convert_to_bool(allow_sending_files)
        self.allows_incoming_traffic = self._convert_to_bool(allows_incoming_traffic)
        self.allows_routing = self._convert_to_bool(allows_routing)
        self.allows_lan_access = self._convert_to_bool(allows_lan_access)
        self.allows_sending_files = self._convert_to_bool(allows_sending_files)
        self.accept_fileshare_automatically = self._convert_to_bool(accept_fileshare_automatically)

    @classmethod
    def from_str(cls, data: str):
        # Split the data into lines, filter out lines that don't contain ':',
        # split each line into key-value pairs, strip whitespace, and convert keys to lowercase
        peer_dict = {
            a.strip().lower(): b.strip()
            for a, b in (
                element.split(':')  # Split each line into key-value pair
                for element in filter(lambda line: len(line.split(':')) == 2, data.split('\n'))  # Filter lines containing ':'
            )
        }

        peer = cls(
                hostname = peer_dict['hostname'],
                nickname = peer_dict["nickname"],
                ip = peer_dict["ip"],
                public_key = peer_dict["public key"],
                os = peer_dict["os"],
                distribution = peer_dict["distribution"],
            )

        # Internal, external peer cases
        if "status" in peer_dict:
            peer.status = peer_dict["status"]
            peer.allow_incoming_traffic = cls._convert_to_bool(peer_dict["allow incoming traffic"])
            peer.allow_routing = cls._convert_to_bool(peer_dict["allow routing"])
            peer.allow_lan_access = cls._convert_to_bool(peer_dict["allow local network access"])
            peer.allow_sending_files = cls._convert_to_bool(peer_dict["allow sending files"])
            peer.allows_incoming_traffic = cls._convert_to_bool(peer_dict["allows incoming traffic"])
            peer.allows_routing = cls._convert_to_bool(peer_dict["allows routing"])
            peer.allows_lan_access = cls._convert_to_bool(peer_dict["allows local network access"])
            peer.allows_sending_files = cls._convert_to_bool(peer_dict["allows sending files"])
            peer.accept_fileshare_automatically = cls._convert_to_bool(peer_dict["accept fileshare automatically"])

        return peer

    def get_peer_name(self, name_type: PeerName) -> str:
        match name_type:
            case PeerName.Hostname:
                return self.hostname
            case PeerName.Ip:
                return self.ip
            case PeerName.Pubkey:
                return self.public_key

    def is_connected(self) -> bool:
        return self.status == "connected"

    @staticmethod
    def _convert_to_str(value):
        return "enabled" if value else "disabled"

    def to_str(self):
        output = [
            f"Hostname: {self.hostname}",
            f"Nickname: {self.nickname}",
        ]

        if self.status is not None:
            output += [
                f"Status: {self.status}",
            ]

        output += [
            f"IP: {self.ip}",
            f"Public Key: {self.public_key}",
            f"OS: {self.os}",
            f"Distribution: {self.distribution}"
        ]

        if self.status is not None:
            output += [
                f"Allow Incoming Traffic: {self._convert_to_str(self.allow_incoming_traffic)}",
                f"Allow Routing: {self._convert_to_str(self.allow_routing)}",
                f"Allow Local Network Access: {self._convert_to_str(self.allow_lan_access)}",
                f"Allow Sending Files: {self._convert_to_str(self.allow_sending_files)}",
                f"Allows Incoming Traffic: {self._convert_to_str(self.allows_incoming_traffic)}",
                f"Allows Routing: {self._convert_to_str(self.allows_routing)}",
                f"Allows Local Network Access: {self._convert_to_str(self.allows_lan_access)}",
                f"Allows Sending Files: {self._convert_to_str(self.allows_sending_files)}",
                f"Accept Fileshare Automatically: {self._convert_to_str(self.accept_fileshare_automatically)}"
            ]

        return output

    def name(self) -> str:
        """Returns nickname if not empty and hostname otherwise."""
        if not self.nickname:
            return self.nickname

        return self.hostname

class PeerList:
    def __init__(self):
        self.this_device: list[Peer] = []
        self.internal_peers: list[Peer] = []
        self.external_peers: list[Peer] = []

    def set_this_device(self, peer_data: str):
        self.this_device = []
        self.this_device.append(Peer.from_str(peer_data))

    def get_this_device(self) -> Peer:
        return self.this_device[0]


    def add_internal_peer(self, peer_data: str) -> None:
        self.internal_peers.append(Peer.from_str(peer_data))

    def get_internal_peer(self) -> Peer | None:
        if len(self.internal_peers) != 0:
            return self.internal_peers[0]
        return None

    def get_all_internal_peers(self) -> list[Peer]:
        return self.internal_peers

    def clear_internal_peer_list(self):
        self.internal_peers = []


    def add_external_peer(self, peer_data: str):
        self.external_peers.append(Peer.from_str(peer_data))

    def get_external_peer(self) -> Peer | None:
        if len(self.external_peers) != 0:
            return self.external_peers[0]
        return None

    def get_all_external_peers(self) -> list[Peer]:
        return self.external_peers

    def clear_external_peer_list(self):
        self.external_peers = []

    def find_peer(self, peer: str) -> Peer:
        for peer_info in self.external_peers + self.internal_peers:
            if peer_info.ip == peer or peer_info.hostname == peer or peer_info.nickname == peer:
                return peer_info
        raise Exception("peer not found")


    def parse_peer_list(self, filter_list: str | None = None) -> list[str]:
        """Builds expected Meshnet peer list string according to passed list of filters."""

        show_internal = True
        show_external = True

        if filter_list is not None:
            for flt in filter_list:
                if flt == "external":
                    show_external = True
                    show_internal = False
                    self.clear_internal_peer_list()

                if flt == "internal":
                    show_internal = True
                    show_external = False
                    self.clear_external_peer_list()

                if flt == "offline":
                    self.clear_internal_peer_list()
                    self.clear_external_peer_list()

        output = ["This device:"]
        output.extend(self.get_this_device().to_str())
        output += [""]

        if show_internal:
            output += ["Local Peers:"]
            if self.get_internal_peer() is not None:
                output.extend(self.get_internal_peer().to_str())
            else:
                output.extend(["[no peers]"])

            if show_external:
                output.extend([""])

        if show_external:
            output += ["External Peers:"]
            if self.get_external_peer() is not None:
                output.extend(self.get_external_peer().to_str())
            else:
                output.extend(["[no peers]"])

        return output


    @classmethod
    def from_str(cls, output: str):
        """Converts output/meshnet peer list string to PeerList object."""

        def remove_text_before_and_keyword(input_string, keyword):
            index = input_string.find(keyword)

            if index != -1:
                return input_string[index + len(keyword):]
            return input_string

        peer_list = get_clean_peer_list(output)
        peer_list_object = cls()

        this_device = peer_list.split("\n\n")[0].replace("This device:\n", "")
        peer_list_object.set_this_device(this_device)

        internal_peers = remove_text_before_and_keyword(peer_list, "Local Peers:\n").split("\n\n\n")[0]
        if "[no peers]" not in internal_peers:
            internal_peer_list = internal_peers.split("\n\n")

            for peer_data in internal_peer_list:
                peer_list_object.add_internal_peer(peer_data)

        external_peers = remove_text_before_and_keyword(peer_list, "External Peers:\n")
        if "[no peers]" not in external_peers:
            external_peer_list = external_peers.split("\n\n")

            for peer_data in external_peer_list:
                peer_list_object.add_external_peer(peer_data)

        return peer_list_object


# Used for test parametrization, when the same test has to be run with different Meshnet alias.
MESHNET_ALIAS = [
    "meshnet",
    "mesh"
]

MSG_PEER_UNKNOWN = "Peer '%s' is unknown."
MSG_PEER_OFFLINE = "Connect to other mesh peer failed - check if peer '%s' is online."
MSG_ROUTING_NEED_NORDLYNX = "NordLynx technology must be set to use this feature."
MSG_ROUTING_SUCCESS = "You are connected to Meshnet exit node '%s'."

MSG_PEER_ROUTING_ALLOW_SUCCESS = "Traffic routing for '%s' has been allowed."
MSG_PEER_ROUTING_ALLOW_ERROR = "Traffic routing for '%s' is already allowed."
MSG_PEER_ROUTING_DENY_SUCCESS =  "Traffic routing for '%s' has been denied."
MSG_PEER_ROUTING_DENY_ERROR = "Traffic routing for '%s' is already denied."

MSG_PEER_INCOMING_ALLOW_SUCCESS = "Incoming traffic for '%s' has been allowed."
MSG_PEER_INCOMING_ALLOW_ERROR = "Incoming traffic for '%s' is already allowed."
MSG_PEER_INCOMING_DENY_SUCCESS = "Incoming traffic for '%s' has been denied."
MSG_PEER_INCOMING_DENY_ERROR = "Incoming traffic for '%s' is already denied."

MSG_PEER_LOCAL_ALLOW_SUCCESS = "Local network access for '%s' has been allowed."
MSG_PEER_LOCAL_ALLOW_ERROR = "Local network access for '%s' is already allowed."
MSG_PEER_LOCAL_DENY_SUCCESS = "Local network access for '%s' has been denied."
MSG_PEER_LOCAL_DENY_ERROR = "Local network access for '%s' is already denied."

MSG_PEER_FILESHARE_ALLOW_SUCCESS = "Fileshare for '%s' has been allowed."
MSG_PEER_FILESHARE_ALLOW_ERROR = "Fileshare for '%s' is already allowed."
MSG_PEER_FILESHARE_DENY_SUCCESS = "Fileshare for '%s' has been denied."
MSG_PEER_FILESHARE_DENY_ERROR = "Fileshare for '%s' is already denied."

MSG_PEER_AUTOACCEPT_ALLOW_SUCCESS = "Automatic fileshare for '%s' has been allowed."
MSG_PEER_AUTOACCEPT_DENY_SUCCESS = "Automatic fileshare for '%s' has been denied."

PERMISSION_SUCCESS_MESSAGE_PARAMETER_SET = [
    ("routing", "allow", MSG_PEER_ROUTING_ALLOW_SUCCESS),
    ("routing", "deny", MSG_PEER_ROUTING_DENY_SUCCESS),
    ("incoming", "allow", MSG_PEER_INCOMING_ALLOW_SUCCESS),
    ("incoming", "deny", MSG_PEER_INCOMING_DENY_SUCCESS),
    ("local", "allow", MSG_PEER_LOCAL_ALLOW_SUCCESS),
    ("local", "deny", MSG_PEER_LOCAL_DENY_SUCCESS),
    ("fileshare", "allow", MSG_PEER_FILESHARE_ALLOW_SUCCESS),
    ("fileshare", "deny", MSG_PEER_FILESHARE_DENY_SUCCESS),
]

PERMISSION_ERROR_MESSAGE_PARAMETER_SET = [
    ("routing", "allow", MSG_PEER_ROUTING_ALLOW_ERROR),
    ("routing", "deny", MSG_PEER_ROUTING_DENY_ERROR),
    ("incoming", "allow", MSG_PEER_INCOMING_ALLOW_ERROR),
    ("incoming", "deny", MSG_PEER_INCOMING_DENY_ERROR),
    ("local", "allow", MSG_PEER_LOCAL_ALLOW_ERROR),
    ("local", "deny", MSG_PEER_LOCAL_DENY_ERROR),
    ("fileshare", "allow", MSG_PEER_FILESHARE_ALLOW_ERROR),
    ("fileshare", "deny", MSG_PEER_FILESHARE_DENY_ERROR),
]

def add_peer(ssh_client: ssh.Ssh,
             tester_allow_fileshare: bool = True,
             tester_allow_routing: bool = True,
             tester_allow_local: bool = True,
             tester_allow_incoming: bool = True,
             peer_allow_fileshare: bool = True,
             peer_allow_routing: bool = True,
             peer_allow_local: bool = True,
             peer_allow_incoming: bool = True):
    """
    Adds QA peer to meshnet.

    Try to minimize usage of this, because there's a weekly invite limit.
    """
    tester_allow_fileshare_arg = f"--allow-peer-send-files={str(tester_allow_fileshare).lower()}"
    tester_allow_routing_arg = f"--allow-traffic-routing={str(tester_allow_routing).lower()}"
    tester_allow_local_arg = f"--allow-local-network-access={str(tester_allow_local).lower()}"
    tester_allow_incoming_arg = f"--allow-incoming-traffic={str(tester_allow_incoming).lower()}"

    peer_allow_fileshare_arg = f"--allow-peer-send-files={str(peer_allow_fileshare).lower()}"
    peer_allow_routing_arg = f"--allow-traffic-routing={str(peer_allow_routing).lower()}"
    peer_allow_local_arg = f"--allow-local-network-access={str(peer_allow_local).lower()}"
    peer_allow_incoming_arg = f"--allow-incoming-traffic={str(peer_allow_incoming).lower()}"

    sh_no_tty.nordvpn.mesh.inv.send(tester_allow_incoming_arg, tester_allow_local_arg, tester_allow_routing_arg, tester_allow_fileshare_arg, PEER_USERNAME)
    local_user = login.get_credentials("default").email
    ssh_client.exec_command(f"yes | nordvpn mesh inv accept {peer_allow_local_arg} {peer_allow_incoming_arg} {peer_allow_routing_arg} {peer_allow_fileshare_arg} {local_user}")

    sh_no_tty.nordvpn.mesh.peer.refresh()


def remove_all_peers():
    """Removes all meshnet peers from local device."""
    peer_list = PeerList.from_str(sh_no_tty.nordvpn.mesh.peer.list())

    for peer in peer_list.get_all_internal_peers() + peer_list.get_all_external_peers():
        sh_no_tty.nordvpn.mesh.peer.remove(peer.hostname)


def remove_all_peers_in_peer(ssh_client: ssh.Ssh):
    """Removes all meshnet peers from peer device."""
    # Execute a refresh so peer is forced to update its' mesh map and realize it's removed
    # already.
    ssh_client.exec_command("nordvpn mesh peer refresh")

    peer_list = PeerList.from_str(ssh_client.exec_command("nordvpn mesh peer list"))

    for peer in peer_list.get_all_internal_peers() + peer_list.get_all_external_peers():
        ssh_client.exec_command(f"nordvpn mesh peer remove {peer.hostname}")


def get_sent_invites(output: str) -> list:
    """Parses list of sent invites from 'nordvpn meshnet inv list' output."""
    emails = []
    for line in output.split("\n"):
        if line.find("Received Invites:") != -1:
            break  # End of sent invites
        if line.find("Email:") != -1:
            emails.append(line.split(" ")[1])
    return emails


def revoke_all_invites():
    """Revokes all sent meshnet invites in local device."""
    output = f"{sh_no_tty.nordvpn.mesh.inv.list()}"  # convert to string, _tty_out false disables colors
    for i in get_sent_invites(output):
        sh_no_tty.nordvpn.mesh.inv.revoke(i)


def revoke_all_invites_in_peer(ssh_client: ssh.Ssh):
    """Revokes all sent meshnet invites in peer device."""
    output = ssh_client.exec_command("nordvpn mesh inv list")
    for i in get_sent_invites(output):
        ssh_client.exec_command(f"nordvpn mesh inv revoke {i}")


def send_meshnet_invite(email):
    try:
        command = ["nordvpn", "meshnet", "invite", "send", email]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        for _ in range(4):
            process.stdin.write('\n')
            process.stdin.flush()

        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()

        if process.returncode != 0:
            raise sh.ErrorReturnCode_1(full_cmd="", stdout=b"", stderr=stdout.split('\n')[-2].encode('utf-8'))

        return stdout.strip().split('\n')[-1]
    except subprocess.CalledProcessError as e:
        print(f"Error occurred: {e}")
        raise sh.ErrorReturnCode_1 from None


def accept_meshnet_invite(ssh_client: ssh.Ssh,
             peer_allow_fileshare: bool = True,
             peer_allow_routing: bool = True,
             peer_allow_local: bool = True,
             peer_allow_incoming: bool = True):

    peer_allow_fileshare_arg = f"--allow-peer-send-files={str(peer_allow_fileshare).lower()}"
    peer_allow_routing_arg = f"--allow-traffic-routing={str(peer_allow_routing).lower()}"
    peer_allow_local_arg = f"--allow-local-network-access={str(peer_allow_local).lower()}"
    peer_allow_incoming_arg = f"--allow-incoming-traffic={str(peer_allow_incoming).lower()}"

    local_user = login.get_credentials("default").email
    output = ssh_client.exec_command(f"yes | nordvpn mesh inv accept {peer_allow_local_arg} {peer_allow_incoming_arg} {peer_allow_routing_arg} {peer_allow_fileshare_arg} {local_user}")
    sh_no_tty.nordvpn.mesh.peer.refresh()

    return output


def deny_meshnet_invite(ssh_client: ssh.Ssh):

    local_user = login.get_credentials("default").email
    output = ssh_client.exec_command(f"yes | nordvpn mesh inv deny {local_user}")

    return output

def validate_input_chain(peer_ip: str, routing: bool, local: bool, incoming: bool, fileshare: bool) -> (bool, str):
    #rules = sh_no_tty.sudo.iptables("-S", "INPUT")
    rules = os.popen("sudo iptables -S INPUT").read()

    fileshare_rule = f"-A INPUT -s {peer_ip}/32 -p tcp -m tcp --dport 49111 -m comment --comment nordvpn-meshnet -j ACCEPT"
    if (fileshare_rule in rules) != fileshare:
        return False, f"Fileshare permissions configured incorrectly, rule expected: {fileshare_rule}\nrules:{rules}"

    incoming_rule = f"-A INPUT -s {peer_ip}/32 -m comment --comment nordvpn-meshnet -j ACCEPT"
    if (incoming_rule in rules) != incoming:
        return False, f"Incoming permissions configured incorrectly, rule expected: {incoming_rule}\nrules:{rules}"

    # If incoming is not enabled, no rules other than fileshare(if enabled) for that peer should be added
    if not incoming:
        if fileshare:
            rules = rules.replace(fileshare_rule, "")
        if peer_ip not in rules:
            return True, ""
        return False, f"Rules for peer({peer_ip}) found in the INCOMING chain but peer does not have the incoming permissions\nrules:\n{rules}"

    incoming_rule_idx = rules.find(incoming_rule)

    for lan in LANS:
        lan_rule = f"-A INPUT -s {peer_ip}/32 -d {lan} -m comment --comment nordvpn -j DROP"
        lan_rule_idx = rules.find(lan_rule)
        if (routing and local) and lan_rule_idx != -1:
            return False, f"LAN/Routing permissions configured incorrectly\nlocal enabled: {local}\nrouting enabled: {routing}\nrules:\n{rules}"
        # verify that lan_rule is located above the local rule
        if lan_rule_idx > incoming_rule_idx:
            return False, f"LAN/Routing rules ineffective(added after incoming traffic rule)\nlocal enabled: {local}\nrouting enabled: {routing}\nrules:\n{rules}"

    return True, ""


def validate_forward_chain(peer_ip: str, routing: bool, local: bool, incoming: bool, fileshare: bool) -> (bool, str):
    _, _ = incoming, fileshare
    #rules = sh.sudo.iptables("-S", "FORWARD")
    rules = os.popen("sudo iptables -S FORWARD").read()

    # This rule is added above the LAN denial rules if both local and routing is allowed to peer, or bellow LAN denial
    # if only routing is allowed.
    routing_enabled_rule = f"-A FORWARD -s {peer_ip}/32 -m comment --comment nordvpn-exitnode-transient -j ACCEPT"
    routing_enabled_rule_index = rules.find(routing_enabled_rule)

    if routing and (routing_enabled_rule_index == -1):
        return False, f"Routing permission not found\nrules:{rules}"
    if not routing and (routing_enabled_rule_index != -1):
        return False, f"Routing permission found\nrules:{rules}"

    for lan in LANS:
        lan_drop_rule = f"-A FORWARD -s 100.64.0.0/10 -d {lan} -m comment --comment nordvpn-exitnode-transient -j DROP"
        lan_drop_rule_index = rules.find(lan_drop_rule)

        # If any peer has routing or local permission, lan block rules should be added, otherwise no rules should be added.
        if (routing or local) and lan_drop_rule_index == -1:
            return False, f"LAN drop rule not added for subnet {lan}\nrules:\n{rules}"
        if (not routing) and (not lan) and lan_drop_rule_index != -1:
            return False, f"LAN drop rule added for subnet {lan}\nrules:\n{rules}"

        if routing:
            # Local is allowed, routing rule should be above LAN block rules to allow peer to access any subnet.
            if local and (lan_drop_rule_index < routing_enabled_rule_index):
                return False, f"LAN drop rule for subnet {lan} added before routing\nrules: {rules}"
            # Local is not allowed, routing rule should be below LAN block rules to deny peer access to local subnets.
            if (not local) and (lan_drop_rule_index > routing_enabled_rule_index):
                return False, f"LAN drop rule for subnet {lan} added after routing\nrules: {rules}"
            continue

        # If routing is not enabled, but lan is enabled, there should be one rule for each local network for the peer.
        # They should be located above the LAN block rules.
        if not local:
            continue

        lan_allow_rule = f"-A FORWARD -s {peer_ip}/32 -d {lan} -m comment --comment nordvpn-exitnode-transient -j ACCEPT"
        lan_allow_rule_index = rules.find(lan_allow_rule)

        if lan_allow_rule not in rules:
            return False, f"LAN allow rule for subnet {lan} not found\nrules:\n{rules}"

        if lan_allow_rule_index > lan_drop_rule_index:
            return False, f"LAN allow rule is added after LAN drop rule\nrules:\n{rules}"

    return True, ""


def set_permission(peer: str, permission: bool, permission_state: bool):
    """Tries to set permission to specified state. Ignores any error messages."""
    with contextlib.suppress(sh.ErrorReturnCode_1):
        sh_no_tty.nordvpn.mesh.peer(permission, permission_state, peer)


def set_permissions(peer: str, routing: bool | None = None, local: bool | None = None, incoming: bool | None = None, fileshare: bool | None = None):
    def bool_to_permission(permission: bool) -> str:
        if permission:
            return "allow"
        return "deny"

    # ignore any failures that might occur when permissions are already configured to the desired value
    if routing is not None:
        sh_no_tty.nordvpn.mesh.peer.routing(bool_to_permission(routing), peer, _ok_code=(0, 1))

    if local is not None:
        sh_no_tty.nordvpn.mesh.peer.local(bool_to_permission(local), peer, _ok_code=(0, 1))

    if incoming is not None:
        sh_no_tty.nordvpn.mesh.peer.incoming(bool_to_permission(incoming), peer, _ok_code=(0, 1))

    if fileshare is not None:
        sh_no_tty.nordvpn.mesh.peer.fileshare(bool_to_permission(fileshare), peer, _ok_code=(0, 1))


def get_clean_peer_list(peer_list: str):
    output = strip_colors.sub('', str(peer_list))
    output = "This " + output.split("This", 1)[-1].strip()
    return output


def is_peer_reachable(peer: Peer, peer_name: PeerName = PeerName.Hostname, ssh_client: ssh.Ssh = None, retry: int = 5) -> bool:
    """Returns True when ping to peer succeeds."""

    if peer_name == PeerName.Hostname:
        peer_hostname = peer.hostname
    elif peer_name == PeerName.Ip:
        peer_hostname = peer.ip
    elif peer_name == PeerName.Nickname:
        peer_hostname = peer.nickname

    if ssh_client is None:
        return network.is_internet_reachable(peer_hostname, 22, retry)
    else:  # noqa: RET505
        work_dir = os.environ.get("WORKDIR")
        # Usage: python3 is_host_alive.py <host> [retries] [delay]
        return "True" in ssh_client.exec_command(f"python3 {work_dir}/test/qa/scripts/is_host_alive.py {peer_hostname} {retry} 1")

def is_connect_successful(output:str, peer_hostname: str):
    return (MSG_ROUTING_SUCCESS % peer_hostname) in output

def get_lines_with_keywords(lines: list[str], keywords: list[str]) -> list:
    """Returns list with elements, that contain specified `keywords`."""
    return [line.strip() for line in lines if all(keyword in line for keyword in keywords)]

def are_peers_connected(ssh_client: ssh.Ssh = None, retry: int = 3) -> None:
    """
    Verifies if local and remote NordVPN mesh peers see each other as connected in peer list.

    Args:
        ssh_client (ssh.Ssh): SSH client to execute commands on the remote system.

    Raises:
        pytest.fail: If peers are not connected after `retry` attempts.
    """

    for refresh_count in range(retry):
        local_peer_list = sh_no_tty.nordvpn.mesh.peer.list()
        remote_peer_list = ssh_client.exec_command("nordvpn mesh peer list")

        if "Status: connected" in local_peer_list and \
            "Status: connected" in remote_peer_list:
            logging.log(f"peer list refresh count: {refresh_count}")
            return

        time.sleep(2)

    logging.log(f"=== local_peer_list ===\n{local_peer_list}\n")
    logging.log(f"=== remote_peer_list ===\n{remote_peer_list}\n")
    pytest.fail("Peers do not see each other as connected.")


def download_remote_peer_logs(ssh_client: ssh.Ssh, dest_logs_path: str) -> None:
    try:
        ssh_client.download_file("/var/log/nordvpn/daemon.log", f"{dest_logs_path}/other-peer-daemon.log")
        ssh_client.download_file("/root/.cache/nordvpn/norduserd.log", f"{dest_logs_path}/norduserd-other.log")
        ssh_client.download_file("/root/.cache/nordvpn/nordfileshare.log", f"{dest_logs_path}/nordfileshare-other.log")
    except Exception as e: # noqa: BLE001
        logging.log(f"failed to download peer logs: {e}")

def create_session(token: str) -> requests.Session:
    """
    Creates and returns a `requests.Session` object with persistent authentication headers.

    Args:
        token (str): The API token used for authentication.

    Returns:
        requests.Session: A session object configured with the token.
    """
    session = requests.Session()
    session.auth = ("token", token)
    session.headers.update({
        "Authorization": f"token:{token}",
        "Content-Type": "application/json",
    })
    return session

def get_machine_identifiers(token: str) -> list:
    """
    Fetches the list of machines and returns all 'identifier' values from the JSON response.

    Args:
        token (str): The API token used for authentication.

    Returns:
        list: A list of machine identifiers (values of the 'identifier' key).
    """
    url = f"{BASE_API}/meshnet/machines"
    identifiers = []
    session = create_session(token)

    try:
        response = session.get(url)
        response.raise_for_status()

        machines = response.json()
        identifiers = [machine["identifier"] for machine in machines]
        logging.log(f'Identifiers: {identifiers}')
    except requests.RequestException as e:
        logging.log(f"Got an error during GET request to fetch list of identifiers: {e}")
    except KeyError:
        logging.log("Error: Unable to find 'identifier' in the response.")
    session.close()
    return identifiers

def delete_machines_by_identifier(token: str, identifiers: list | None = None) -> None:
    """
    Deletes all machines using the provided list of identifiers.

    Args:
        token (str): The API token used for authentication.
        identifiers (list): A list of machine identifiers to delete.

    Returns:
        None
    """
    identifiers = identifiers or get_machine_identifiers(token)
    base_url = f"{BASE_API}/meshnet/machines"
    session = create_session(token)

    for identifier in identifiers:
        url = f"{base_url}/{identifier}"
        try:
            response = session.delete(url)
            if response.status_code == 204:
                logging.log(f"Successfully deleted machine with identifier: {identifier}")
            elif response.status_code == 404:
                logging.log(f"Machine with identifier {identifier} not found.")
            else:
                logging.log(f"Failed to delete machine {identifier}: {response.status_code} {response.reason}")
        except requests.RequestException as e:
            logging.log(f"Got an error during DELETE request for {identifier}: {e}")
    session.close()
