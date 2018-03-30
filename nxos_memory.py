#!/usr/bin/env python3
"""
This Nagios check is used to grab the memory usage stats from a Cisco device
running NXOS using the NXAPI. It accepts a warning and critical value in using
the percentage of used memory.

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
PARSER.add_argument("-w", "--warning", dest="warning_percent", type=int,
                    default=70)
PARSER.add_argument("-w", "--critical", dest="critical_percent", type=int,
                    default=80)
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
    Query the memory used on the device returned by the "show system
    resources" CLI commmand and compare to the warning and
    critical values.
    """
    # Define the actual Cisco NXOS command issued to the device and parse it
    # with the json module.
    raw_resource_info = nxos_show("show system resources")
    json_resource_info= json.loads(raw_resource_info)

    memory_used = (json_resource_info["ins_api"]
                                        ["outputs"]
                                        ["output"]
                                        ["body"]
                                        ["memory_usage_used"])
    memory_total = (json_resource_info["ins_api"]
                                        ["outputs"]
                                        ["output"]
                                        ["body"]
                                        ["memory_usage_total"])

    memory_percent = (float(memory_used) / float(memory_total)) * 100

    if (memory_percent >= ARGS.warning_percent and memory_percent <
        ARGS.critical_percent):

        # 0:.2f rounds to two decimal places
        print("WARNING - Memory usage at {0:.2f} percent"
              .format(memory_percent))
        sys.exit(1)

    if (memory_percent >= ARGS.critical_percent):

        print("CRITICAL - Memory usage at {0:.2f} percent"
              .format(memory_percent))
        sys.exit(2)

    print("OK: Memory usage at {0:.2f} percent".format(memory_percent))
    sys.exit(0)


if __name__ == '__main__':
    main()
