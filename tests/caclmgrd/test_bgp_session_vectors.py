"""
caclmgrd per-session BGP permit test vectors (kamelnetworks fork).

Each vector describes a CONFIG_DB BGP_NEIGHBOR layout and the TCP/179 permits
the generator is expected to produce for it. "expected_permits" lists
(iptables binary, peer match) pairs; the test only requires that an INPUT
ACCEPT rule for TCP/179 with that peer match exists, and deliberately does not
pin the destination (-d) match, which depends on the BGP ACL semantics chosen
in kamelnetworks/sonic-buildimage#38.

Scenarios tracked by kamelnetworks/sonic-buildimage#28 (and #9 for the
unnumbered case).
"""

_SKELETON = {
    "DEVICE_METADATA": {
        "localhost": {
            "type": "ToRRouter",
        }
    },
    "FEATURE": {},
}


def _config(bgp_neighbor):
    cfg = dict(_SKELETON)
    cfg["BGP_NEIGHBOR"] = bgp_neighbor
    return cfg


CACLMGRD_BGP_SESSION_TEST_VECTOR = [
    [
        "IPv4 numbered peer with IPv4 local_addr",
        {
            "config_db": _config({
                "10.0.0.1": {
                    "name": "peer4",
                    "asn": "65001",
                    "local_addr": "10.0.0.0",
                },
            }),
            "expected_permits": [
                ("iptables", ["-s", "10.0.0.1"]),
            ],
        },
    ],
    [
        "IPv6 numbered peer with IPv6 local_addr",
        {
            "config_db": _config({
                "fc00::2": {
                    "name": "peer6",
                    "asn": "65001",
                    "local_addr": "fc00::1",
                },
            }),
            "expected_permits": [
                ("ip6tables", ["-s", "fc00::2"]),
            ],
        },
    ],
    [
        "IPv4 numbered peer without local_addr (issue #28)",
        {
            "config_db": _config({
                "10.200.0.0": {
                    "name": "eos1",
                    "asn": "65002",
                },
            }),
            "expected_permits": [
                ("iptables", ["-s", "10.200.0.0"]),
            ],
        },
    ],
    [
        "IPv6 numbered peer without local_addr (issue #28)",
        {
            "config_db": _config({
                "fc00:200::": {
                    "name": "eos1-v6",
                    "asn": "65002",
                },
            }),
            "expected_permits": [
                ("ip6tables", ["-s", "fc00:200::"]),
            ],
        },
    ],
    [
        "IPv4 numbered peer with interface-valued local_addr (issue #28)",
        {
            "config_db": _config({
                "10.200.0.0": {
                    "name": "eos1",
                    "asn": "65002",
                    "local_addr": "Loopback0",
                },
            }),
            "expected_permits": [
                ("iptables", ["-s", "10.200.0.0"]),
            ],
        },
    ],
    [
        "VRF-scoped IPv4 numbered peer with local_addr",
        {
            "config_db": _config({
                "Vrf1|10.1.0.1": {
                    "name": "vrfpeer",
                    "asn": "65003",
                    "local_addr": "10.1.0.0",
                },
            }),
            "expected_permits": [
                ("iptables", ["-s", "10.1.0.1"]),
            ],
        },
    ],
    [
        "Unnumbered (interface) peer without local_addr (issue #9)",
        {
            "config_db": _config({
                "Ethernet64": {
                    "name": "unnumbered",
                    "asn": "65004",
                },
            }),
            "expected_permits": [
                ("ip6tables", ["-i", "Ethernet64"]),
            ],
        },
    ],
    [
        "Mixed: numbered peers with and without local_addr plus unnumbered peer",
        {
            "config_db": _config({
                "10.0.0.1": {"name": "a", "asn": "65001", "local_addr": "10.0.0.0"},
                "10.200.0.0": {"name": "b", "asn": "65002"},
                "fc00:200::": {"name": "c", "asn": "65002"},
                "Ethernet64": {"name": "d", "asn": "65004"},
            }),
            "expected_permits": [
                ("iptables", ["-s", "10.0.0.1"]),
                ("iptables", ["-s", "10.200.0.0"]),
                ("ip6tables", ["-s", "fc00:200::"]),
                ("ip6tables", ["-i", "Ethernet64"]),
            ],
        },
    ],
]
