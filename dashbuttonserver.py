import json

from scapy.all import *


CONFIGURATION = None
DASH_BUTTON_MACS = []


def main():
    read_configuration('config.json')
    start_server()


def read_configuration(path):
    global CONFIGURATION
    global DASH_BUTTON_MACS

    print 'Reading configuration'

    with open(path) as input_file:
        CONFIGURATION = json.load(input_file)

    DASH_BUTTON_MACS += CONFIGURATION['buttons'].values()


def start_server():
    interface = CONFIGURATION['interface']

    print 'Dash Button Server listening on', interface

    sniff(iface=str(interface), prn=handle_packet, filter='udp', lfilter=filter_dash_button_macs, store=0)


def filter_dash_button_macs(packet):
    global DASH_BUTTON_MACS

    return packet.src in DASH_BUTTON_MACS


def handle_packet(packet):
    if DHCP in packet:
        options = packet[DHCP].options

        for option in options:
            if isinstance(option, tuple):
                if 'requested_addr' in option:
                    packet_mac = packet.src

                    if packet_mac == CONFIGURATION['buttons']['wilson_jones_dash_button']:
                        do_wilson_jones_dash_button_action()
                    elif packet_mac == CONFIGURATION['buttons']['repurpose_dash_button']:
                        do_repurpose_dash_button_action()
                    elif packet_mac == CONFIGURATION['buttons']['the_laundress_dash_button']:
                        do_the_laundress_dash_button_action()


def do_wilson_jones_dash_button_action():
    print 'Wilson Jones Button Pushed'


def do_repurpose_dash_button_action():
    print 'Repurpose Button Pushed'


def do_the_laundress_dash_button_action():
    print 'The Laundress Button Pushed'


if __name__ == '__main__':
    main()

