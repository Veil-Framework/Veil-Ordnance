'''

This is going to be the main class that directs and controls execution of
Veil-Ordnance

'''

import glob
import imp


class Conductor:

    def __init__(self):

        # all encoders within the encoders directory
        self.active_encoders = {}

        # Payloads currently within the x86 payload directory
        self.active_payloads = {}

        # Load all encoder modules
        self.load_encoders()

        # Load all payload modules
        self.load_payloads()

    def generate(self):
        # This is the main function where everything is called from
        for payload in self.active_payloads.itervalues():
            print payload.name

    def load_encoders(self):
        for name in glob.glob('encoders/*.py'):
            if name.endswith(".py") and ("__init__" not in name):
                loaded_encoder = imp.load_source(
                    name.replace("/", ".").rstrip('.py'), name)
                self.active_encoders[name] = loaded_encoder.EncoderModule()
        return

    def load_payloads(self):
        for name in glob.glob('payloads/x86/*.py'):
            if name.endswith(".py") and ("__init__" not in name):
                loaded_payloads = imp.load_source(
                    name.replace("/", ".").rstrip('.py'), name)
                self.active_payloads[name] = loaded_payloads.PayloadModule()
        return
