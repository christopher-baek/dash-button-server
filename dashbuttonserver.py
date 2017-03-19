import json
import logging
import requests

from scapy.all import *


FORMATTER = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

CONSOLE_HANDLER = logging.StreamHandler()
CONSOLE_HANDLER.setLevel(logging.DEBUG)
CONSOLE_HANDLER.setFormatter(FORMATTER)

LOGGER = logging.getLogger('dash-button-server')
LOGGER.setLevel(logging.DEBUG)
LOGGER.addHandler(CONSOLE_HANDLER)


CONFIGURATION = None
DASH_BUTTON_MACS = []
IFTTT_URL_FORMAT = 'https://maker.ifttt.com/trigger/{event}/with/key/{key}'


def main():
    read_configuration('config.json')
    start_server()


def read_configuration(path):
    global CONFIGURATION
    global DASH_BUTTON_MACS

    LOGGER.info('Reading configuration')

    with open(path) as input_file:
        CONFIGURATION = json.load(input_file)

    DASH_BUTTON_MACS += CONFIGURATION['buttons'].values()


def start_server():
    interface = CONFIGURATION['interface']

    LOGGER.info('Dash Button Server listening on {}'.format(interface))

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
    LOGGER.info('Wilson Jones Button Pushed')
    execute_ifttt_event('wilson_jones_dash_button')


def do_repurpose_dash_button_action():
    LOGGER.info('Repurpose Button Pushed')
    execute_ifttt_event('repurpose_dash_button')


def do_the_laundress_dash_button_action():
    LOGGER.info('The Laundress Button Pushed')
    execute_ifttt_event('the_laundress_dash_button')


def execute_ifttt_event(event_name):
    LOGGER.info('Executing IFTTT event {}'.format(event_name))

    url = IFTTT_URL_FORMAT.format(event=event_name, key=CONFIGURATION['ifttt_key'])

    response = requests.get(url)

    if response.status_code == 200:
        LOGGER.info('Request executed successfully')
    else:
        LOGGER.error('Error executing request!')


if __name__ == '__main__':
    main()

