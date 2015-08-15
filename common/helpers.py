'''

This file will contain functions that help for random tasks throughout
Veil-Ordnance and may wish to be re-used elsewhere, because functions
have feelings too.

'''

import argparse
import sys


def cli_parser(internal_encoders, internal_payloads):

    # Command line argument parser
    parser = argparse.ArgumentParser(
        add_help=False,
        description="Ordnance disposal!")
    parser.add_argument(
        '-h', '-?', '--h', '-help', '--help', action="store_true",
        help=argparse.SUPPRESS)

    shell_in = parser.add_argument_group('Shellcode Generation Options')
    shell_in.add_argument(
        "-p", "--payload", metavar="Payload Type", default=None,
        help="Payload type (bind_tcp or rev_tcp)")
    shell_in.add_argument(
        "--ip", "--domain", metavar="IP Address", default=None,
        help="IP Address to connect back to")
    shell_in.add_argument(
        '--port', metavar="Port Number", default=4444, type=int,
        help="Port number to connect to.")
    shell_in.add_argument(
        '--list-payloads', default=False, action='store_true',
        help="Lists all available payloads.")

    shell_in = parser.add_argument_group('Encoder Options')
    shell_in.add_argument(
        "-e", "--encoder", metavar="Encoder Name", default=None,
        help="Name of Shellcode Encoder to use")
    shell_in.add_argument(
        "-b", "--bad-chars", metavar="\\x00\\x0a..", default=None,
        help="Bad characters to avoid")
    shell_in.add_argument(
        '--list-encoders', default=False, action='store_true',
        help="Lists all available encoders.")
    shell_in.add_argument(
        '--print-stats', default=False, action='store_true',
        help="Print information about the encoded shellcode.")

    args = parser.parse_args()

    # If you don't give any cli options, display help menu
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()

    if args.h:
        parser.print_help()
        sys.exit()

    if args.list_payloads:
        print " Encoder name    =>    Description"
        for payload in internal_payloads.itervalues():
            print payload.cli_name + " => " + payload.name
        sys.exit()

    if args.list_encoders:
        for encoder in internal_encoders.itervalues():
            print encoder.name + " => " + encoder.cli_name
        sys.exit()

    # Checks if you have a payload set, and if not, to error out
    if args.payload is None:
        print "[*] Error: Please select a payload to generate!"
        sys.exit(1)

    # Checks to make sure you specify an IP address unless using a bind payload
    if args.ip is None and args.payload.lower() != "bind_tcp":
        print "[*] Error: Please provide an IP address!"
        sys.exit(1)

    # Checks to make sure a valid port is used
    if 0 < args.port < 65536:
        pass
    else:
        print "[*] Error: You did not provide a valid port number!"
        print "[*] Error: Please provide a number between 1-65535!"
        sys.exit(1)

    # Need to fix this if statement to iterate over loaded encoders and flag
    # if user specified encoder is not found
    if args.encoder is not None:
        encoder_not_found = True
        for encoder in internal_encoders.itervalues():
            if args.encoder.lower() != encoder.cli_name:
                pass
            else:
                encoder_not_found = False

        # If encoder nor found, alert user and exit
        if encoder_not_found:
            print "[*] Error: The encoder you selected was not found!"
            print "[*] Error: Please check available encoders and run again!"
            sys.exit(1)

    # Checks to make sure if you are using an encoder, to supply bad characters
    if args.encoder is not None and args.bad_chars is None:
        print "[*] Error: Please provide bad characters to avoid with the encoder."
        print "[*] Error: If no bad characters, please re-run without using an encoder."
        sys.exit(1)

    return args
