import json

from scapy.all import *


CONFIGURATION = None


def main():
    read_configuration('config.json')
    start_server()


def read_configuration(path):
    global CONFIGURATION

    print 'Reading configuration'

    with open(path) as input_file:
        CONFIGURATION = json.load(input_file)


def start_server():
    interface = CONFIGURATION['interface']

    print 'Dash Button Server listening on', interface

    sniff(iface=str(interface), prn=handle_packet, filter='arp', store=0, count=0)


def handle_packet(packet):
    if ARP in packet: # ARP layer exists
        if packet[ARP].op == 1: # who-has (request)
            packet_mac = packet[ARP].hwsrc

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

