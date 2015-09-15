#!/usr/bin/env python


from common import helpers
from common import orchestra


if __name__ == "__main__":

    cli_args = helpers.cli_parser()

    # instantiate the orchesta object and call the main conductor
    the_conductor = orchestra.Conductor(cli_args)

    the_conductor.generate_main(cli_args)
