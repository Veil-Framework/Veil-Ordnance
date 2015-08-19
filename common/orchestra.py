'''

This is going to be the main class that directs and controls execution of
Veil-Ordnance

'''

import glob
import imp


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

    def generate(self, cli_arguments):
        # This is the main function where everything is called from
        for full_path, payload_mod in self.active_payloads.itervalues():
            if cli_arguments.payload.lower() == payload_mod.cli_name:
                payload_mod.set_attrs(cli_arguments)
        
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

