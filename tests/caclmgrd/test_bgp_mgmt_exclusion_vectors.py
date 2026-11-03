"""
caclmgrd BGP peer-group/range fallback test vectors
(kamelnetworks/sonic-buildimage#30).

Each vector is a CONFIG_DB snapshot in which no BGP_NEIGHBOR row exists but a
BGP_PEER_GROUP or BGP_PEER_RANGE row does, which makes caclmgrd emit its
"allow BGP from everyone" fallback. The expectation lives in
caclmgrd_bgp_mgmt_exclusion_test.py and is deliberately weak so that it does
not presume the semantics chosen in kamelnetworks/sonic-buildimage#38.
"""

_SKELETON = {
    "ACL_RULE": {},
    "ACL_TABLE": {},
    "DEVICE_METADATA": {
        "localhost": {
            "type": "ToRRouter",
        }
    },
    "FEATURE": {},
}


def _config(**tables):
    cfg = dict(_SKELETON)
    cfg.update(tables)
    return cfg


CACLMGRD_BGP_FALLBACK_TEST_VECTOR = [
    [
        "BGP_PEER_RANGE only (dynamic/passive IPv4 listen range)",
        {
            "config_db": _config(
                BGP_PEER_RANGE={
                    "BGPSLBPassive": {
                        "name": "BGPSLBPassive",
                        "ip_range": ["10.255.0.0/25"],
                        "src_address": "10.1.0.32",
                    },
                },
            ),
        },
    ],
    [
        "BGP_PEER_RANGE only (IPv6 listen range)",
        {
            "config_db": _config(
                BGP_PEER_RANGE={
                    "BGPV6Passive": {
                        "name": "BGPV6Passive",
                        "ip_range": ["fc00:255::/64"],
                        "src_address": "fc00:1::32",
                    },
                },
            ),
        },
    ],
    [
        "BGP_PEER_GROUP only",
        {
            "config_db": _config(
                BGP_PEER_GROUP={
                    "PEER_V4": {
                        "name": "PEER_V4",
                        "asn": "65100",
                    },
                },
            ),
        },
    ],
    [
        "BGP_PEER_GROUP plus one explicit IPv4 neighbor",
        {
            "config_db": _config(
                BGP_PEER_GROUP={
                    "PEER_V4": {
                        "name": "PEER_V4",
                        "asn": "65100",
                    },
                },
                BGP_NEIGHBOR={
                    "10.200.0.0": {
                        "name": "eos1",
                        "asn": "64001",
                        "local_addr": "10.200.0.1",
                    },
                },
            ),
        },
    ],
]
