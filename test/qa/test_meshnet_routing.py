import socket
import time

import pytest
import sh

import lib
from lib import daemon, logging, meshnet, network, ssh
from lib.shell import sh_no_tty

ssh_client = ssh.Ssh("qa-peer", "root", "root")


def setup_module(module):  # noqa: ARG001
    meshnet.TestUtils.setup_module(ssh_client)


def teardown_module(module):  # noqa: ARG001
    meshnet.TestUtils.teardown_module(ssh_client)


def setup_function(function):  # noqa: ARG001
    meshnet.TestUtils.setup_function(ssh_client)


def teardown_function(function):  # noqa: ARG001
    meshnet.TestUtils.teardown_function(ssh_client)


@pytest.mark.parametrize("lan_discovery", [True, False])
@pytest.mark.parametrize("local", [True, False])
def test_killswitch_exitnode(lan_discovery: bool, local: bool):
    my_ip = meshnet.PeerList.from_str(sh_no_tty.nordvpn.mesh.peer.list()).get_this_device().ip
    peer_ip = meshnet.PeerList.from_str(sh_no_tty.nordvpn.mesh.peer.list()).get_external_peer().ip

    try:
        ssh_client.exec_command(f"nordvpn mesh peer incoming allow {my_ip}")
    except RuntimeError as err:
        if "already allowed" not in err.args[0]:
            raise
    try:
        ssh_client.exec_command(f"nordvpn mesh peer routing allow {my_ip}")
    except RuntimeError as err:
        if "already allowed" not in err.args[0]:
            raise
    try:
        ssh_client.exec_command(f"nordvpn mesh peer local {'allow' if local else 'deny'} {my_ip}")
    except RuntimeError as err:
        if "already allowed" not in err.args[0]:
            raise
    try:
        ssh_client.exec_command(f"nordvpn set lan-discovery {'on' if lan_discovery else 'off'}")
    except RuntimeError as err:
        if "already set" not in err.args[0]:
            raise

    # Start disconnected from exitnode
    assert network.is_available()

    # Connect to exitnode
    sh_no_tty.nordvpn.mesh.peer.connect(peer_ip)
    assert daemon.is_connected()
    assert network.is_available()

    # Enable killswitch on exitnode
    ssh_client.exec_command("nordvpn set killswitch enabled")
    assert daemon.is_connected()
    assert network.is_not_available()

    # Disconnect from exitnode
    sh_no_tty.nordvpn.disconnect()
    assert not daemon.is_connected()
    assert network.is_available()

    # Connect to exitnode
    sh_no_tty.nordvpn.mesh.peer.connect(peer_ip)
    assert daemon.is_connected()
    assert network.is_not_available()

    # Disable killswitch on exitnode
    ssh_client.exec_command("nordvpn set killswitch disabled")
    assert daemon.is_connected()
    assert network.is_available()

    # Disconnect from exitnode
    sh_no_tty.nordvpn.disconnect()
    assert not daemon.is_connected()
    assert network.is_available()


def test_route_traffic_to_each_other():
    peer_list = meshnet.PeerList.from_str(sh_no_tty.nordvpn.mesh.peer.list())
    peer_hostname = peer_list.get_external_peer().hostname
    peer_pubkey = peer_list.get_external_peer().public_key

    output = sh_no_tty.nordvpn.mesh.peer.connect(peer_pubkey)
    assert meshnet.is_connect_successful(output, peer_hostname)

    local_hostname = peer_list.get_this_device().hostname
    output = ssh_client.exec_command(f"nordvpn mesh peer connect {local_hostname}")
    assert meshnet.is_connect_successful(output, local_hostname)

    assert network.is_not_available()
    assert ssh_client.network.is_not_available()

    sh_no_tty.nordvpn.disconnect()
    ssh_client.exec_command("nordvpn disconnect")


def test_routing_deny_for_peer_is_peer_no_netting():
    peer_list = meshnet.PeerList.from_str(sh_no_tty.nordvpn.mesh.peer.list())
    peer_hostname = peer_list.get_external_peer().hostname

    this_device = peer_list.get_this_device()
    output = ssh_client.exec_command("nordvpn mesh peer connect " + this_device.ip)
    assert meshnet.is_connect_successful(output, this_device.hostname)

    sh_no_tty.nordvpn.mesh.peer.routing.deny(peer_hostname)

    assert ssh_client.network.is_not_available()

    ssh_client.exec_command("nordvpn disconnect")


def test_route_to_nonexistant_node():
    nonexistant_node_name = "penguins-are-cool.nord"

    with pytest.raises(sh.ErrorReturnCode_1) as ex:
        sh_no_tty.nordvpn.mesh.peer.connect(nonexistant_node_name)

    expected_message = meshnet.MSG_PEER_UNKNOWN % nonexistant_node_name

    assert expected_message in str(ex)


def test_route_to_peer_status_valid():
    peer_hostname = meshnet.PeerList.from_str(sh_no_tty.nordvpn.mesh.peer.list()).get_external_peer().hostname

    peer_nick = "a-A-a"
    sh_no_tty.nordvpn.mesh.peer.nick.set(peer_hostname, peer_nick)
    output = sh_no_tty.nordvpn.mesh.peer.connect(peer_nick)
    assert meshnet.is_connect_successful(output, peer_nick)

    connect_time = time.monotonic()

    time.sleep(5)
    sh.ping("-c", "1", "-w", "1", "103.86.96.100")

    status_output = sh_no_tty.nordvpn.status().lstrip("\r -")
    status_time = time.monotonic()

    # Split the data into lines, filter out lines that don't contain ':',
    # split each line into key-value pairs, strip whitespace, and convert keys to lowercase
    status_info = {
        a.strip().lower(): b.strip()
        for a, b in (
            element.split(":")  # Split each line into key-value pair
            for element in filter(lambda line: len(line.split(":")) == 2, status_output.split("\n"))  # Filter lines containing ':'
        )
    }

    logging.log("status_info: " + str(status_info))
    logging.log("status_info: " + str(sh_no_tty.nordvpn.status()))

    assert "Connected" in status_info["status"]
    assert peer_hostname in status_info["hostname"]
    assert peer_nick in status_info["server"]
    assert socket.gethostbyname(peer_nick) in status_info["ip"]
    assert "NORDLYNX" in status_info["current technology"]
    assert "UDP" in status_info["current protocol"]

    transfer_data = status_info["transfer"].split(" ")
    transfer_received = float(transfer_data[0])
    transfer_sent = float(transfer_data[3])
    assert transfer_received >= 0
    assert transfer_sent > 0

    time_connected = int(status_info["uptime"].split(" ")[0])
    time_passed = status_time - connect_time
    if "minute" in status_info["uptime"]:
        time_connected_seconds = int(status_info["uptime"].split(" ")[2])
        assert time_connected * 60 + time_connected_seconds >= time_passed - 1 and time_connected * 60 + time_connected_seconds <= time_passed + 1
    else:
        assert time_connected >= time_passed - 1 and time_connected <= time_passed + 1

    sh_no_tty.nordvpn.disconnect()


@pytest.mark.skip(reason="Test suit exits, before test can be completed.")
def test_route_to_peer_that_is_disconnected():
    peer_hostname = meshnet.PeerList.from_str(sh_no_tty.nordvpn.mesh.peer.list()).get_external_peer().name()

    ssh_client.exec_command("nordvpn set mesh off")

    time.sleep(140)

    with pytest.raises(sh.ErrorReturnCode_1) as ex:
        sh_no_tty.nordvpn.mesh.peer.connect(peer_hostname)

    expected_message = meshnet.MSG_PEER_OFFLINE % peer_hostname

    assert expected_message in str(ex)


@pytest.mark.parametrize(("tech", "proto", "obfuscated"), lib.TECHNOLOGIES_NO_MESHNET)
def test_route_traffic_to_peer_wrong_tech(tech, proto, obfuscated):
    lib.set_technology_and_protocol(tech, proto, obfuscated)

    peer_hostname = meshnet.PeerList.from_str(sh_no_tty.nordvpn.mesh.peer.list()).get_external_peer().name()

    with pytest.raises(sh.ErrorReturnCode_1) as ex:
        sh_no_tty.nordvpn.mesh.peer.connect(peer_hostname)

    assert meshnet.MSG_ROUTING_NEED_NORDLYNX in str(ex)
