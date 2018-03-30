#!/usr/bin/env python3
"""
This Nagios check is used to grab the temperature value from sensors of a Cisco
device running NXOS using the NXAPI. The device has its own temperature
thresholds (different for each sensor) and this compares the 'MinorThresh'
(warning temperature) against the 'CurTemp' (current temperature) values
returned when running a "show environment temperature" CLI command.

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
    Iterate through all temperature sensors on the device.

    Use WARNING threshold that is stored on the device itself as the
    CRITICAL value for Nagios. We do this because we want to be alerted if it
    reaches the warning function, since the device will automatically shut
    down if it reaches its own critical value.
    """
    # Define the actual Cisco NXOS command issued to the device and parse it
    # with the json module.
    raw_temperature = nxos_show("show environment temperature")
    json_temperature = json.loads(raw_temperature)

    # Count the number of temperature sensors on the device so we know how many
    # to iterate through
    sensor_count = len(
        json_temperature["ins_api"]
        ["outputs"]
        ["output"]
        ["body"]
        ["TABLE_tempinfo"]
        ["ROW_tempinfo"])

    # Iterate through all temperature sensors and either stop when you reach
    # one that has reached the threshold (exit CRITICAL), or stop when you've
    # determined all sensors are under the threshold (exit OK)
    for x in range(0, sensor_count):
        sensor_name = (json_temperature["ins_api"]
                       ["outputs"]
                       ["output"]
                       ["body"]
                       ["TABLE_tempinfo"]
                       ["ROW_tempinfo"]
                       [x]
                       ['sensor'])
        current_temp = int(json_temperature["ins_api"]
                           ["outputs"]
                           ["output"]
                           ["body"]
                           ["TABLE_tempinfo"]
                           ["ROW_tempinfo"]
                           [x]
                           ['curtemp'])
        critical_temp = int(json_temperature["ins_api"]
                            ["outputs"]
                            ["output"]
                            ["body"]
                            ["TABLE_tempinfo"]
                            ["ROW_tempinfo"]
                            [x]
                            ['minthres'])

        if current_temp >= critical_temp:
            print("CRITICAL - Current temp for sensor {} is {}, "
                  "threshold set to {}".format(sensor_name,
                                               current_temp,
                                               critical_temp))
            sys.exit(2)

    print("OK: All sensor temperatures within thresholds")
    sys.exit(0)


if __name__ == '__main__':
    main()
