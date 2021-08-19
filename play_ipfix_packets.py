from ipfix import craft_packet
from scapy.all import send

import argparse

from time import sleep, time
from random import uniform
import ipaddress
import math

# https://stackoverflow.com/questions/4194948/python-argparse-is-there-a-way-to-specify-a-range-in-nargs
def required_length(nmin,nmax):
    class RequiredLength(argparse.Action):
        def __call__(self, parser, args, values, option_string=None):
            if not nmin<=len(values)<=nmax:
                msg='argument "{f}" requires between {nmin} and {nmax} arguments'.format(
                    f=self.dest,nmin=nmin,nmax=nmax)
                raise argparse.ArgumentTypeError(msg)
            setattr(args, self.dest, values)
    return RequiredLength

def parse_args():
    parser = argparse.ArgumentParser(description='Stresstest BMP collector')
    parser.add_argument(
        '-c',
        '--collector-ip',
        default='127.0.0.1',
        dest="collector_ip",
        type=str,
        help="IP of the BMP collector",
    )

    parser.add_argument(
        '-p',
        '--collector-port',
        default=9991,
        dest="collector_port",
        type=int,
        help="Port of the BMP collector",
    )

    parser.add_argument(
        '-S',
        '--start-ip',
        dest="start_ip",
        type=str,
        required=True,
        help="First IP to use as a client",
    )

    parser.add_argument(
        '-F',
        '--prefix',
        dest="prefix",
        type=str,
        required=True,
        help="Prefix assigned to the interface",
    )

    parser.add_argument(
        '-C',
        '--number-clients',
        dest="number_clients",
        type=int,
        required=True,
        help="First IP to use as a client",
    )

    parser.add_argument(
        '-D',
        '--test-duration',
        dest="test_duration",
        type=int,
        default=0,
        help="If 0, never stop the test, else stop the test after test-duration seconds",
    )

    parser.add_argument(
        '-w',
        '--wait-time-ms',
        dest="wait_time_ms",
        nargs='+',
        action=required_length(1, 2),
        required=True,
        type=int,
        help="An integer for a static sleep, or a range (two numbers) to generate a uniormily distributed random number that is used to sleep between each packet sent. Sleep is in ms.",
    )

    args = parser.parse_args()
    return args


def main():
    args = parse_args()

    start = ipaddress.IPv4Address(args.start_ip)
    network = ipaddress.IPv4Network(f'{args.start_ip}/{args.prefix}', strict=False)

    start_time = time()
    count_pkt = 0
    try:
        while True:
            ip_it = network.hosts()
            ip = next(ip_it)
            while ip < start:
                ip = next(ip_it)
                continue

            for i in range(1, args.number_clients + 1):
                pkt = craft_packet(ip, args.collector_ip, (i+1000)%65535, args.collector_port)
                send(pkt, verbose=False)
                print('.', end='', flush=True)
                count_pkt += 1
                ip = next(ip_it)

                if len(args.wait_time_ms) == 1:
                    sleep(args.wait_time_ms[0] / 1000)
                else:
                    sleep(uniform(args.wait_time_ms[0], args.wait_time_ms[1]) / 1000)

                if args.test_duration != 0 and args.test_duration <= time() - start_time:
                    print('all done :)')
                    print(f'Sent {count_pkt} packets')
                    return

    except KeyboardInterrupt:
        print('control+c - Stopping')
        print('all done :)')
        print(f'Sent {count_pkt} packets')

if __name__ == '__main__':
  main()