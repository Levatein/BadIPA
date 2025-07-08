#! /usr/bin/env python3.9
import argparse
import logging
import sys
from badIPA.api import BadIPA_API


# just disable ssl warnings
import urllib3
urllib3.disable_warnings()


class CustomFormatter(logging.Formatter):
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(levelname)s - %(message)s"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        #logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        #logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


with open('dict/commands') as f:
    commands = f.read().split('\n')


with open('dict/services') as f:
    services = f.read().split('\n')


def parse_args():
    parser = argparse.ArgumentParser(
        add_help=True, description='For filling FreeIPA with data',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-u', '--username', action='store', help='Domain admin username')
    parser.add_argument('-k', '--kerberos', action='store_true', help='Use $KRB5CCNAME for auth')
    parser.add_argument('-p', '--password', action='store', help='Domain admin password')
    parser.add_argument('-dc', '--domain-controller', metavar='HOST', action='store', help='DC hostname')
    parser.add_argument('-ip', action='store', help='IP address')
    parser.add_argument('-size', action='store', help='Max: 400. Count of users for creation')
    parser.add_argument('-v', action='store_true', help='Debug mode')
    return parser


def main():
    parser = parse_args()
    args = parser.parse_args()
    logger = logging.getLogger('badIPA')
    logger.setLevel(logging.DEBUG if args.v else logging.INFO)
    ch = logging.StreamHandler()
    ch.setFormatter(CustomFormatter())
    logger.addHandler(ch)

    if (args.kerberos is False) and (args.username is None or args.password is None or args.domain_controller is None):
        logger.error('Please specify DC, username and password or use $KRB5CCNAME')
        parser.print_help()
        exit(1)

    client = BadIPA_API(args.domain_controller, args.username, args.password, logger, kerberos_login=args.kerberos, size=args.size)
    client.add_groups()
    client.add_hostgroups()
    client.add_netgroups()
    client.add_groups_to_groups()

    client.add_users()
    client.add_hosts()
    client.add_services(services)

    client.add_sudocmd_group()
    client.add_sudo_cmd(commands)
    client.add_sudo_rules()
    client.add_sudo_hosts()

    client.add_hbac()

    client.add_roles()
    client.add_role_members()
    client.add_permissions_and_privileges()


if __name__ == '__main__':
    main()
