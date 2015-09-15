'''

This is going to be the main class that directs and controls execution of
Veil-Ordnance

'''

import glob
import imp
import sys
from encoders import *
from payloads.x86 import *


class Conductor:

    def __init__(self, command_line_arguments):

        # all encoders within the encoders directory
        self.active_encoders = {}

        # Payloads currently within the x86 payload directory
        self.active_payloads = {}

        # Load all encoder modules
        self.load_encoders(command_line_arguments)

        # Load all payload modules
        self.load_payloads(command_line_arguments)

    def generate_main(self, cli_arguments):

        # Check to see if we're just listing payloads
        if cli_arguments.list_payloads:
            print "\nAvailable Payload Modules"
            print "Command Line Name => Description"
            print "-" * 79
            for mod_name in self.active_payloads.itervalues():
                print mod_name.cli_name + " => " + mod_name.name
            sys.exit()

        # Check to see if we're just listing encoders
        if cli_arguments.list_encoders:
            print "\nAvailable Encoder Modules"
            print "Command Line Name => Description"
            print "-" * 79
            for encoder_module in self.active_encoders.itervalues():
                print encoder_module.cli_name + " => " + encoder_module.name
            sys.exit()

        # This is the main function where everything is called from
        # Iterate over payloads and find the user selected payload module
        for payload_module in self.active_payloads.itervalues():
            if cli_arguments.payload.lower() == payload_module.cli_name:
                payload_module.gen_shellcode()

                if cli_arguments.bad_chars is not None and cli_arguments.encoder is not None:

                    # Iterate over encoders until the one is found that's being used
                    for selected_encoder in self.active_encoders.itervalues():
                        if cli_arguments.encoder.lower() == selected_encoder.cli_name:
                            # pass the shellcode into the encoder
                            selected_encoder.set_shellcode(payload_module.customized_shellcode)
                            # Encode the shellcode
                            selected_encoder.do_the_magic()
                            break

                    if cli_arguments.print_stats:
                        selected_encoder.all_the_stats(cli_arguments)

                    # Print the encoded shellcode
                    print selected_encoder.encoded_shellcode
                    break

                # If not encoding, then just print the shellcode
                else:
                    # Print the encoded shellcode
                    print payload_module.customized_shellcode
                    break

            # This hits when not provided with a valid payload
            else:
                print "[*] Error: The payload you selected was not found!"
                print "[*] Error: Please check available payloads and run again!"
                sys.exit(1)

        return

    def load_encoders(self, cli_args):
        for name in glob.glob('encoders/*.py'):
            if name.endswith(".py") and ("__init__" not in name):
                loaded_encoder = imp.load_source(
                    name.replace("/", ".").rstrip('.py'), name)
                self.active_encoders[name] = loaded_encoder.EncoderModule(cli_args)
        return

    def load_payloads(self, cli_args):
        for name in glob.glob('payloads/x86/*.py'):
            if name.endswith(".py") and ("__init__" not in name):
                loaded_payloads = imp.load_source(
                    name.replace("/", ".").rstrip('.py'), name)
                self.active_payloads[name] = loaded_payloads.PayloadModule(cli_args)
        return
