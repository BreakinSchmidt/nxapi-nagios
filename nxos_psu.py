#!/usr/bin/env python3
"""
This Nagios check is used to grab the power supply status from sensors of a
Cisco device running NXOS using the NXAPI. The device has its own PSU fault
detection and this parses the status of each power supply
when running a "show environment power" CLI command.

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
    Iterate through all PSU sensors on the device.

    Look for the status returned by the "show environment power" CLI commmand.
    """
    # Define the actual Cisco NXOS command issued to the device and parse it
    # with the json module.
    raw_psu_info = nxos_show("show environment power")
    json_psu_info= json.loads(raw_psu_info)

    # Count the number of power supplies on the device so we know how many
    # to iterate through
    psu_count = len(
        json_psu_info["ins_api"]
        ["outputs"]
        ["output"]
        ["body"]
        ["powersup"]
        ["TABLE_psinfo"]
        ["ROW_psinfo"])

    # Iterate through all power supplies and either stop when you reach
    # one that is not returning an OK status, or stop when you've
    # determined all PSUs are reading as OK (exit OK)
    for x in range(0, psu_count):
        psu_id = (json_psu_info["ins_api"]
                       ["outputs"]
                       ["output"]
                       ["body"]
                       ["powersup"]
                       ["TABLE_psinfo"]
                       ["ROW_psinfo"]
                       [x]
                       ['psnum'])
        psu_status = (json_psu_info["ins_api"]
                           ["outputs"]
                           ["output"]
                           ["body"]
                           ["powersup"]
                           ["TABLE_psinfo"]
                           ["ROW_psinfo"]
                           [x]
                           ['ps_status'])

        if psu_status != "Ok":
            print("CRITICAL - PSU Number {} status is {}, ".format(psu_id,
                                                                   psu_status))
            sys.exit(2)

    print("OK: All power supplies return OK status")
    sys.exit(0)


if __name__ == '__main__':
    main()
