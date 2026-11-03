"""
    caclmgrd BGP table subscription test vectors (kamelnetworks/sonic-buildimage#29)

    Each vector is one CONFIG_DB change event. "regenerates" says whether the
    daemon's main loop must schedule a control plane ACL regeneration for it.
    The per-session BGP permits are derived from BGP_NEIGHBOR, BGP_PEER_RANGE
    and BGP_PEER_GROUP, so any add/change/delete in those tables has to go
    through the same locking/debounce path as an ACL_TABLE change.
"""

CACLMGRD_BGP_SUBSCRIPTION_CONFIG_DB = {
    "DEVICE_METADATA": {
        "localhost": {
            "hostname": "sonic",
            "type": "LeafRouter",
        }
    },
    "FEATURE": {
        "bgp": {
            "auto_restart": "enabled",
            "state": "enabled",
        }
    },
}

CACLMGRD_BGP_SUBSCRIPTION_TEST_VECTOR = [
    [
        # Control case: this path already works and proves the harness does.
        "ACL_TABLE_SET",
        {
            "table": "ACL_TABLE",
            "event": ("SSH_ONLY", "SET", [("policy_desc", "SSH_ONLY"), ("services", "SSH"),
                                          ("stage", "ingress"), ("type", "CTRLPLANE")]),
            "regenerates": True,
        },
    ],
    [
        # New numbered peer must get its TCP/179 permit without a restart.
        "BGP_NEIGHBOR_SET_IPV4",
        {
            "table": "BGP_NEIGHBOR",
            "event": ("10.200.0.0", "SET", [("asn", "65100"), ("local_addr", "10.200.0.1"),
                                            ("name", "eos1")]),
            "regenerates": True,
        },
    ],
    [
        # New unnumbered (interface) peer must get its fe80::/10 permit.
        "BGP_NEIGHBOR_SET_INTERFACE",
        {
            "table": "BGP_NEIGHBOR",
            "event": ("Ethernet112", "SET", [("asn", "65100"), ("name", "sw3")]),
            "regenerates": True,
        },
    ],
    [
        # VRF-qualified key (VRF|peer); must not be mistaken for an ACL_RULE key.
        "BGP_NEIGHBOR_SET_VRF",
        {
            "table": "BGP_NEIGHBOR",
            "event": ("Vrf1|10.200.0.0", "SET", [("asn", "65100"), ("local_addr", "10.200.0.1"),
                                                 ("name", "eos1-vrf1")]),
            "regenerates": True,
        },
    ],
    [
        # Removed peer must lose its permit without a restart.
        "BGP_NEIGHBOR_DEL",
        {
            "table": "BGP_NEIGHBOR",
            "event": ("10.200.0.0", "DEL", []),
            "regenerates": True,
        },
    ],
    [
        "BGP_PEER_RANGE_SET",
        {
            "table": "BGP_PEER_RANGE",
            "event": ("BGPSLBPassive", "SET", [("name", "BGPSLBPassive"), ("ip_range", "10.255.0.0/25"),
                                               ("src_address", "10.1.0.32")]),
            "regenerates": True,
        },
    ],
    [
        "BGP_PEER_RANGE_DEL",
        {
            "table": "BGP_PEER_RANGE",
            "event": ("BGPSLBPassive", "DEL", []),
            "regenerates": True,
        },
    ],
    [
        "BGP_PEER_GROUP_SET",
        {
            "table": "BGP_PEER_GROUP",
            "event": ("PEER_V4", "SET", [("name", "PEER_V4")]),
            "regenerates": True,
        },
    ],
    [
        "BGP_PEER_GROUP_DEL",
        {
            "table": "BGP_PEER_GROUP",
            "event": ("PEER_V4", "DEL", []),
            "regenerates": True,
        },
    ],
]
