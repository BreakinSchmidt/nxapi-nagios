#!/usr/bin/env python3
"""
This Nagios check is used to grab the fan status from sensors of a Cisco
device running NXOS using the NXAPI. The device has its own fan fault detection
and this parses the status of each fan when running a "show environment
temperature" CLI command.

The device needs to have the nxapi enabled with "feature nxapi" in
configuration mode.
"""

import argparse
import json
import sys
import requests
import urllib3

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
    Iterate through all fan sensors on the device.

    Look for the status returned by the "show environment fan" CLI commmand.
    """
    # Define the actual Cisco NXOS command issued to the device and parse it
    # with the json module.
    raw_fan_info = nxos_show("show environment fan")
    json_fan_info= json.loads(raw_fan_info)

    # Count the number of fans on the device so we know how many
    # to iterate through
    fan_count = len(
        json_fan_info["ins_api"]
        ["outputs"]
        ["output"]
        ["body"]
        ["fandetails"]
        ["TABLE_faninfo"]
        ["ROW_faninfo"])

    # Iterate through all fans and either stop when you reach
    # one that is not returning an OK status, or stop when you've
    # determined all fans are reading as OK (exit OK)
    for x in range(0, fan_count):
        fan_name = (json_fan_info["ins_api"]
                       ["outputs"]
                       ["output"]
                       ["body"]
                       ["fandetails"]
                       ["TABLE_faninfo"]
                       ["ROW_faninfo"]
                       [x]
                       ['fanname'])
        fan_status = (json_fan_info["ins_api"]
                           ["outputs"]
                           ["output"]
                           ["body"]
                           ["fandetails"]
                           ["TABLE_faninfo"]
                           ["ROW_faninfo"]
                           [x]
                           ['fanstatus'])

        if fan_status != "Ok":
            print("CRITICAL - {} status is {}, ".format(fan_name, fan_status))
            sys.exit(2)

    print("OK: All fans return OK status")
    sys.exit(0)


if __name__ == '__main__':
    main()
