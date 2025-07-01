#!/usr/bin/env python3

# check_fortinet_vuln.py
# A tool to verify if a Fortinet firewall is vulnerable to exploits by comparing
# the HTTP ETag header against known vulnerable ETags in EGBL.config.
# Designed for Python 3.13 with clear, descriptive naming and robust CLI handling.
# Outputs results to a JSON file with a user-specified suffix.

import argparse
import json
import os
import pathlib
import sys
from typing import Final

import requests
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL verification warnings for HTTPS requests to Fortinet devices, as
# some devices may use self-signed certificates.
disable_warnings(InsecureRequestWarning)


def display_usage_instructions():
    """
    Print a formatted banner with usage instructions, including author credits and
    acknowledgments to NSA, Equation Group, and Shadow Brokers for the disclosure.
    This is used when the user requests help via --help or provides invalid arguments.
    """
    usage_banner = """
######## Fortinet Firewall Vulnerability Scanner ############
# Author:      Fabio Natalucci                              #
# Twitter:     @fabionatalucci                              #
# Website:     https://www.fabionatalucci.it                #
#                   Acknowledgments                         #
#           NSA and Equation Group                          #
#      Shadow Brokers for public disclosure                 #
#                                                           #
# Updater:              Evil2997                            #
# github:    https://github.com/Evil2997                    #
#                                                           #
#############################################################
"""
    print(usage_banner)


def verify_configuration_file_exists():
    """
    Check if the EGBL.config file exists in the current working directory.
    This file contains mappings of ETag values to vulnerable Fortinet devices,
    including model, firmware version, and stack addresses.

    Raises:
        SystemExit: Exits with code 2 if EGBL.config is not found.
    """
    configuration_file_path = "EGBL.config"
    if os.path.isfile(configuration_file_path):
        print(f"## Configuration file '{configuration_file_path}' found successfully.")
    else:
        print(f"## ERROR: Configuration file '{configuration_file_path}' not found in current directory.")
        sys.exit(2)


def scan_fortinet_for_vulnerability(target_ip_address):
    """
    Perform a vulnerability scan on a Fortinet firewall by sending an HTTPS GET request
    to the target IP address, extracting the ETag header, and checking if it matches
    known vulnerable ETags in EGBL.config.

    Args:
        target_ip_address (str): The IP address of the Fortinet firewall to scan.

    Returns:
        dict: A dictionary containing scan results:
              - ip_address: The target IP address.
              - vulnerability_status: 'vulnerable', 'not_vulnerable', or 'no_etag'.
              - etag_value: The extracted ETag value or None if not present.
              - error_message: Error details if the scan failed, else None.

    Raises:
        SystemExit: Exits with code 1 if the HTTPS request fails.
    """
    scan_result = {
        "ip_address": target_ip_address,
        "vulnerability_status": "unknown",
        "etag_value": None,
        "error_message": None
    }

    # Send HTTPS GET request to the target Fortinet device
    try:
        http_response = requests.get(
            f"https://{target_ip_address}",
            verify=False,  # Skip SSL verification for self-signed certificates
            timeout=10  # Set a 10-second timeout to avoid hanging
        )
    except requests.exceptions.RequestException as connection_error:
        scan_result["vulnerability_status"] = "error"
        scan_result["error_message"] = str(connection_error)
        print(f"## ERROR: Failed to connect to {target_ip_address}: {connection_error}")
        return scan_result

    # Check if the ETag header is present in the HTTP response
    if "ETag" not in http_response.headers:
        scan_result["vulnerability_status"] = "no_etag"
        scan_result["error_message"] = "No ETag header returned; likely not a Fortinet device or not vulnerable."
        print(f"\n## WARNING: No ETag header returned by {target_ip_address}")
        print("----> LIKELY NOT A FORTINET DEVICE OR NOT VULNERABLE")
        return scan_result

    # Extract and process the ETag header: remove quotes and take the last part after splitting by '_'
    etag_value = http_response.headers["ETag"].replace('"', "").split("_", 2)[-1]
    scan_result["etag_value"] = etag_value

    # Read EGBL.config to check if the ETag indicates a vulnerable device
    configuration_file_path = "EGBL.config"
    with open(configuration_file_path, "r", encoding="utf-8") as config_file:
        config_file_content = config_file.read()

    # Determine vulnerability based on ETag presence in EGBL.config
    if etag_value in config_file_content:
        scan_result["vulnerability_status"] = "vulnerable"
        print(f"\n----> VULNERABLE ! (ETag: {etag_value})")
    else:
        scan_result["vulnerability_status"] = "not_vulnerable"
        print(f"\n----> NOT VULNERABLE (ETag: {etag_value})")

    return scan_result


def save_scan_results_to_json(scan_result, output_json_file_path: pathlib.Path):
    """
    Save the scan results to a JSON file at the specified path.

    Args:
        scan_result (dict): The dictionary containing scan results.
        output_json_file_path (str): The path to the output JSON file.

    Raises:
        SystemExit: Exits with code 3 if the JSON file cannot be written.
    """
    try:
        with output_json_file_path.open("w", encoding="utf-8") as json_file:
            json.dump(scan_result, json_file, indent=4, ensure_ascii=False)
        print(f"## Scan results saved to '{output_json_file_path}'.")
    except IOError as json_write_error:
        print(f"## ERROR: Failed to write scan results to '{output_json_file_path}': {json_write_error}")
        sys.exit(3)


def parse_command_line_arguments():
    """
    Parse command-line arguments using argparse, requiring a target IP address
    and optionally accepting a suffix for the output JSON file.

    Returns:
        argparse.Namespace: Parsed arguments containing:
                            - target_ip_address: The IP address to scan.
                            - output_json_suffix: Suffix for the JSON output file.
    """
    argument_parser = argparse.ArgumentParser(
        description=(
            "Fortinet Firewall Vulnerability Scanner: Checks if a Fortinet firewall "
            "is vulnerable by comparing its HTTP ETag header against known vulnerable "
            "ETags in EGBL.config. Outputs results to a JSON file."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True
    )

    # Required argument: Target IP address
    argument_parser.add_argument(
        "--target",
        type=str,
        required=True,
        help="The IPv4 address of the Fortinet firewall to scan (e.g., 192.168.1.1)."
    )

    # Optional argument: Suffix for the output JSON file
    argument_parser.add_argument(
        "--output",
        type=str,
        required=True,
        help=(
            "Suffix for the output JSON file (default: 'scan_results'). "
            "The file will be named '<suffix>.json' in the current directory."
        )
    )

    # Display the usage banner before the help message
    display_usage_instructions()

    return argument_parser.parse_args()


def main():
    """
    Main function to orchestrate the Fortinet firewall vulnerability scan.
    - Parses command-line arguments.
    - Verifies the EGBL.config file.
    - Scans the target IP for vulnerabilities.
    - Saves results to a JSON file.

    Exits with appropriate status codes:
        - 0: Successful execution.
        - 2: Missing EGBL.config or invalid arguments.
        - 3: Failure to write JSON output file.
    """
    # Parse command-line arguments
    args = parse_command_line_arguments()
    target_ip_address = args.target
    output_json_file_path = args.output

    MAIN_DIRECTORY: Final[pathlib.Path] = pathlib.Path(__file__).parents[0]
    OUTPUT_FILE: Final[pathlib.Path] = pathlib.Path(output_json_file_path)
    OUTPUT_JSON: Final[pathlib.Path] = MAIN_DIRECTORY / OUTPUT_FILE.relative_to("/")

    # Log the start of the scan
    print(f"## Initiating vulnerability scan for IP address: {target_ip_address}")

    # Verify that EGBL.config exists
    print("## Verifying configuration file...")
    verify_configuration_file_exists()

    # Perform the vulnerability scan
    print("## Scanning for vulnerabilities...")
    scan_result = scan_fortinet_for_vulnerability(target_ip_address)

    # Save the scan results to a JSON file
    print("## Saving scan results...")
    save_scan_results_to_json(scan_result, OUTPUT_JSON)


if __name__ == "__main__":
    main()
