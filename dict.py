from typing import Any

dict_configuration: dict[str, Any] = {
    "sniffer": {
        1: {
            "command": "-f",
            "reference": "--filter",
            "type": str,
            "choices": ["tcp", "udp", "icmp"],
            "default": "",
            "help": "Filter for your report: TCP, UDP, ICMP, ("" -> Stands for general)"
            },
        2: {
            "command": "-i",  # ifaces
            "reference": "--dst",
            "type": str,
            "nargs": "+",
            "help": "How many packets you want to review"
        },
        3: {
            "command": "-c",
            "reference": "--count",
            "type": int,
            "help": "How many packets you want to review" 
        }
    },
    "scanner": {
        1: {
            "command": "-ip",
            "reference": "--dst",
            "type": str,
            "help": "IP Address Destiny"
        },
        2: {
            "command": "-p",
            "reference": "--ports",
            "type": int,
            "help": "Ports to review"
        }
    },
    "packet_creator": {
        1: {
            "command": "-t",
            "reference": "--ttl",
            "type": int,
            "default": 10,
            "required": True
        },
        2: {
            "command": "-d",
            "reference": "--dst",
            "type": str,
            "required": True
        },
        3: {
            "command": "-s",
            "reference": "--src",
            "type": str,
        },
        4: {
            "command": "-f",
            "reference": "--flags",
            "choices": ["MF", "evil"],
            "type": str,
            "default": None,
            "required": False
        }
    },
    "syn_scan": {
        1: {
            "command": "-i",
            "reference": "--dst",
            "type": str,
            "help": "Direction Port For Scanning"
        },        
        2: {
            "command": "-sp",
            "reference": "--sport",
            "type": int,
            "help": "Source Port"
        },
        3: {
            "command": "-dp",
            "reference": "--dports",
            "type": int,
            "nargs": "+",
            "help": "Direction Port For Scanning"
        },
        4: {
            "command": "-p",
            "reference": "--ports",
            "type": int,
            "nargs": "+",
            "help": "Ports to review"
        }
    }
}
