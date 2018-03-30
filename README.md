# nxapi-nagios
A collection of nagios scripts for Cisco NXOS that query the NXAPI (no SNMP involved)

These scripts were tested with a Cisco 92160YC-X (9K). Please let me know if you have issues with other models.

## Prerequisites


### Packages
python3
python-requests

### Device Configuration

NXAPI must be turned on with 'feature nxapi'.

## Usage

Most of these scripts will use NXOS's set thresholds and status checks instead of accepting values for warning and critical.
I think this helps makes the scripts more plug-and-play, but feel free to fork or submit changes. 

nxos_memory will accept a -c and -w flag for threshholds, but default to 70 for warning and 80 for critical.

If you are using a self-signed certificate for your device, use the --disable-cert-check flag.

Example:
```
nxos_fan.py -H <hostname> -u <user> -p <password> --disable-cert-check
```
