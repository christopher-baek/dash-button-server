from scapy.all import *


WILSON_JONES_DASH_BUTTON_MAC = '44:65:0d:f5:f1:0f'
REPURPOSE_DASH_BUTTON_MAC = 'ac:63:be:49:8c:f0'
THE_LAUNDRESS_DASH_BUTTON_MAC = '50:f5:da:e7:84:5a'


def main():
    print 'Dash Button Server Listening...'
    sniff(iface='wlan0', prn=handle_packet2, filter='arp', store=0, count=0)


def handle_packet2(packet):
    if ARP in packet:
        if packet[ARP].hwsrc == WILSON_JONES_DASH_BUTTON_MAC:
            packet.show()


def handle_packet(packet):
    if ARP in packet: # ARP layer exists
        if packet[ARP].op == 1: # who-has (request)
            packet_mac = packet[ARP].hwsrc

            if packet_mac == WILSON_JONES_DASH_BUTTON_MAC:
                packet.show()
                do_wilson_jones_dash_button_action()
            elif packet_mac == REPURPOSE_DASH_BUTTON_MAC:
                do_repurpose_dash_button_action()
            elif packet_mac == THE_LAUNDRESS_DASH_BUTTON_MAC:
                do_the_laundress_dash_button_action()


def do_wilson_jones_dash_button_action():
    print 'Wilson Jones Button Pushed'


def do_repurpose_dash_button_action():
    print 'Repurpose Button Pushed'


def do_the_laundress_dash_button_action():
    print 'The Laundress Button Pushed'


if __name__ == '__main__':
    main()

