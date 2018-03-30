#!/usr/bin/env python3
"""
This Nagios check is used to grab the status of the vPC domain from a Cisco
device running NXOS using the NXAPI. The check looks to make sure the vPC
peer adjacency is formed and the peer-link is alive.

The device needs to have the nxapi enabled with "feature nxapi" in
configuration mode.
"""

import argparse
import json
import sys
import requests
import urllib3
import re

# Accept flag arguments into the parser
PARSER = argparse.ArgumentParser()
PARSER.add_argument("-H", "--hostname", dest="hostname", required="true")
PARSER.add_argument("-u", "--user", dest="user", required="true")
PARSER.add_argument("-p", "--password", dest="password", required="true")
PARSER.add_argument("-s", "--disable-cert-check", dest="disable_cert_check",
                    action="store_true")

ARGS = PARSER.parse_args()

# Disable SSL warnings if the certificate check is turned off
if ARGS.disable_cert_check == True:
    urllib3.disable_warnings()

# Define the API URL with hostname plus the /ins NXOS POST location
URL = ("https://" + ARGS.hostname + "/ins")


def nxos_show(command):
    """
    Return JSON formatted result of show command.

    Args:
        command: The command to use with show.

    Returns:
        A dict mapping keys to the corresponding data fetched.
    """
    payload = {
        "ins_api": {
            "version": "1.0",
            "type": "cli_show",
            "chunk": "0",
            "sid": "1",
            "input": command,
            "output_format": "json"
        }
    }

    if ARGS.disable_cert_check == True:
        nxos_response = requests.post(URL,
                                      verify=False,
                                      auth=(ARGS.user, ARGS.password),
                                      json=payload)
        return nxos_response.text

    else:
        nxos_response = requests.post(URL,
                                      auth=(ARGS.user, ARGS.password),
                                      json=payload)
        return nxos_response.text


def main():
    """
    Look at the global vPC status to make sure the vPC peer relationship
    is healthy.
    """
    # Define the actual Cisco NXOS command issued to the device and parse it
    # with the json module.
    raw_vpc = nxos_show("show vpc")
    json_vpc = json.loads(raw_vpc)

    vpc_peer_status = (json_vpc["ins_api"]
                       ["outputs"]
                       ["output"]
                       ["body"]
                       ["vpc-peer-status"])
    vpc_keepalive_status = (json_vpc["ins_api"]
                           ["outputs"]
                           ["output"]
                           ["body"]
                           ["vpc-peer-keepalive-status"])
    vpc_role = (json_vpc["ins_api"]
                            ["outputs"]
                            ["output"]
                            ["body"]
                            ["vpc-role"])

    # If peer status is not Ok, exit CRITICAL

    if vpc_peer_status != "peer-ok":
        print("CRITICAL - Current peer status for vPC domain is {}"
        .format(vpc_peer_status))
        sys.exit(2)

    # If peer keepalive status is not alive, exit CRITICAL

    if vpc_keepalive_status != "peer-alive":
        print("CRITICAL - Current peer keepalive status for vPC domain is {}"
        .format(vpc_keepalive_status))
        sys.exit(2)

    print("OK: VPC domain has an established peer relationship. Role: " + vpc_role)
    sys.exit(0)


if __name__ == '__main__':
    main()
