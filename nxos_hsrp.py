#!/usr/bin/env python3
"""
This Nagios check is used to grab the status of every HSRP group from a Cisco
device running NXOS using the NXAPI. If the group is active on the device, it
returns OK with no further check. If the group is standby on the device, it
checks to make sure a standby address is known, and then returns OK. If the
group is not in standby or active, then a CRITICAL result triggers.

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
    Iterate through all HSRP groups on the device.

    If the group is active on the device, it returns OK with no further check.
    If the group is standby on the device, it checks to make sure a standby
    address is known, and then returns OK. If not, it returns CRITICAL. If the
    group is not in standby or active, then a CRITICAL result triggers.
    """
    # Define the actual Cisco NXOS command issued to the device and parse it
    # with the json module.
    raw_hsrp = nxos_show("show hsrp brief")
    json_hsrp = json.loads(raw_hsrp)

    # Count the number of HSRP groups on the device so we know how many
    # to iterate through
    group_count = len(
        json_hsrp["ins_api"]
        ["outputs"]
        ["output"]
        ["body"]
        ["TABLE_grp_detail"]
        ["ROW_grp_detail"])

    '''
    Define a regex match statement to match an IP address. This one is
    not truly an IP address match (since 255 is the highest octet value),
    but a bad result is always NOT formatted like an IP address, so we don't
    need to be accurate
    '''

    valid_ip = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

    # Iterate through all HSRP groups
    for x in range(0, group_count):
        vlan_id = (json_hsrp["ins_api"]
                       ["outputs"]
                       ["output"]
                       ["body"]
                       ["TABLE_grp_detail"]
                       ["ROW_grp_detail"]
                       [x]
                       ['sh_if_index'])
        group_state = (json_hsrp["ins_api"]
                           ["outputs"]
                           ["output"]
                           ["body"]
                           ["TABLE_grp_detail"]
                           ["ROW_grp_detail"]
                           [x]
                           ['sh_group_state'])
        standby_addr = (json_hsrp["ins_api"]
                            ["outputs"]
                            ["output"]
                            ["body"]
                            ["TABLE_grp_detail"]
                            ["ROW_grp_detail"]
                            [x]
                            ['sh_standby_router_addr'])

        # If group state is not Active or Standby, exit CRITICAL

        if (group_state != "Active" and group_state != "Standby"):
            print("CRITICAL - Current status for HSRP group {} is {}"
            .format(vlan_id, group_state))
            sys.exit(2)

        # If group state is active but the standby router IP is 0.0.0.0 or
        # not an IP address, exit CRITICAL

        if (group_state == "Active"):

            iptest = valid_ip.match(standby_addr)

            if standby_addr == "0.0.0.0":
                print("CRITICAL - Current status for standby device on "
                    "{} is unknown".format(vlan_id,
                                           standby_addr))
                sys.exit(2)

            elif iptest:
                continue

            else:
                print("CRITICAL - Current status for standby device on "
                      "{} is {}".format(vlan_id,
                                        standby_addr))
                sys.exit(2)

    print("OK: All HSRP groups are functional and available")
    sys.exit(0)


if __name__ == '__main__':
    main()
