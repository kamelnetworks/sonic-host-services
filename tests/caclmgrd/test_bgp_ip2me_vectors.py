"""
    caclmgrd BGP vs. ip2me test vectors (kamelnetworks/sonic-buildimage#71)

    A switch with interface IPs but no BGP_NEIGHBOR in CONFIG_DB, i.e. BGP
    configured in vtysh (split mode, docker_routing_config_mode unset or
    "split"). The issue: caclmgrd emits no TCP/179 permit, so the ip2me
    "-d <interface IP> -j DROP" rules drop every inbound BGP SYN.
"""

INTERFACE_CONFIG = {
    "LOOPBACK_INTERFACE": {
        "Loopback0": {},
        "Loopback0|10.1.0.1/32": {},
        "Loopback0|fc00:1::1/128": {},
    },
    "VLAN_INTERFACE": {},
    "PORTCHANNEL_INTERFACE": {},
    "INTERFACE": {
        "Ethernet0": {},
        "Ethernet0|10.200.0.1/31": {},
        "Ethernet0|fc00:200::1/127": {},
    },
    "MGMT_INTERFACE": {
        "eth0|172.18.0.100/24": {
            "gwaddr": "172.18.0.1"
        }
    },
    "FEATURE": {
        "bgp": {
            "auto_restart": "enabled",
            "state": "enabled",
        }
    },
    # Deliberately no BGP_NEIGHBOR / BGP_PEER_GROUP / BGP_PEER_RANGE.
}


def _with_metadata(localhost):
    config = dict(INTERFACE_CONFIG)
    config["DEVICE_METADATA"] = {"localhost": localhost}
    return config


CACLMGRD_BGP_IP2ME_CONFIG_VECTOR = [
    [
        "docker_routing_config_mode unset",
        {"config_db": _with_metadata({"hostname": "sw2", "type": "LeafRouter"})},
    ],
    [
        "docker_routing_config_mode split",
        {"config_db": _with_metadata({"hostname": "sw2", "type": "LeafRouter",
                                      "docker_routing_config_mode": "split"})},
    ],
]
