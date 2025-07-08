#! /usr/bin/env python3.9
from python_freeipa import ClientMeta
from python_freeipa import exceptions as ipa_exceptions
import argparse

import urllib3
urllib3.disable_warnings()


class BadIPA_cleaner(object):
    def __init__(self, dc, username, password, verify_ssl=False, verbose=False, kerberos_login=False):
        self.dc = dc
        self.domain = '.'.join(self.dc.split('.')[1:]).lower()
        if not kerberos_login:
            self.auth(username, password, verify_ssl)
        else:
            self.kerberos_auth()


    def auth(self, username, password, verify_ssl):
        # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client.Client.login
        self.client = ClientMeta(self.dc, verify_ssl=verify_ssl)
        self.client.login(username, password)


    def kerberos_auth(self):
        # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client.Client.login_kerberos
        try:
            self.client.login_kerberos()
        except ipa_exceptions.Unauthorized as error:
            print('An exception occurred:', error)
            exit(1)
    

    def clear_object(self, ipa_object_type, field_name, filter=None):
        ipa_find = getattr(self.client, f'{ipa_object_type}_find')
        ipa_del = getattr(self.client, f'{ipa_object_type}_del')
        ipa_objects = ipa_find()
        result = ipa_objects['result']
        if filter:
            for ipa_object in result:
                name = ipa_object[field_name][0]
                if name not in filter:
                    ipa_del(name)
            print(f'{len(result)-len(filter)} {ipa_object_type}s deleted')
        else:
            for ipa_object in result:
                name = ipa_object[field_name][0]
                ipa_del(name)
            print(f'{len(result)} {ipa_object_type}s deleted')
    

    def helper(self, ipa_object_type, field_name):
        ipa_find = getattr(self.client, f'{ipa_object_type}_find')
        names = []
        for finded in ipa_find(o_sizelimit=0)['result']:
            names.append(finded[field_name][0])
        print(names)


    def clear_all(self):
        self.clear_object('user', 'uid', ['admin'])
        self.clear_object('host', 'cn', [f'{self.dc}'])
        self.clear_object('service', 'krbcanonicalname', [f'HTTP/{self.dc}@{self.domain.upper()}', f'dogtag/{self.dc}@{self.domain.upper()}', f'ldap/{self.dc}@{self.domain.upper()}'])
        self.clear_object('group', 'cn', ['admins', 'editors', 'ipausers', 'trust admins'])
        self.clear_object('hostgroup', 'cn', ['ipaservers'])
        self.clear_object('netgroup', 'cn')
        self.clear_object('sudocmdgroup', 'cn')
        self.clear_object('sudocmd', 'sudocmd')
        self.clear_object('sudorule', 'cn')
        self.clear_object('hbacrule', 'cn', ['allow_all', 'allow_systemd-user'])
        self.clear_object('role', 'cn', ['Enrollment Administrator', 'helpdesk', 'IT Security Specialist', 'IT Specialist', 'Security Architect', 'Subordinate ID Selfservice User', 'User Administrator'])
        self.clear_object('privilege', 'cn', ['ADTrust Agents', 'Automember Readers', 'Automember Task Administrator', 'Automount Administrators', 'CA Administrator', 'Certificate Administrators', 'Certificate Identity Mapping Administrators', 'Delegation Administrator', 'DNS Administrators', 'DNS Servers', 'External IdP server Administrators', 'Group Administrators', 'HBAC Administrator', 'Host Administrators', 'Host Enrollment', 'Host Group Administrators', 'IPA Masters Readers', 'Kerberos Ticket Policy Readers', 'Modify Group membership', 'Modify Users and Reset passwords', 'Netgroups Administrators', 'Passkey Administrators', 'PassSync Service', 'Password Policy Administrator', 'Password Policy Readers', 'RBAC Readers', 'Replication Administrators', 'SELinux User Map Administrators', 'Service Administrators', 'Stage User Administrators', 'Stage User Provisioning', 'Subordinate ID Administrators', 'Subordinate ID Selfservice Users', 'Sudo Administrator', 'User Administrators', 'Vault Administrators', 'Write IPA Configuration'])
        self.clear_object('permission', 'cn', ['System: Add Automount Keys', 'System: Add Automount Locations', 'System: Add Automount Maps', 'System: Add CA', 'System: Add CA ACL', 'System: Add Certmap Rules', 'System: Add DNS Entries', 'System: Add External IdP server', 'System: Add Group Password Policy costemplate', 'System: Add Groups', 'System: Add HBAC Rule', 'System: Add HBAC Service Groups', 'System: Add HBAC Services', 'System: Add Hostgroups', 'System: Add Hosts', 'System: Add krbPrincipalName to a Host', 'System: Delete CA', 'System: Delete CA ACL', 'System: Delete Certificate Profile', 'System: Delete Certmap Rules', 'System: Delete External IdP server', 'System: Delete Group Password Policy costemplate', 'System: Delete HBAC Rule', 'System: Delete HBAC Service Groups', 'System: Delete HBAC Services', 'System: Enroll a Host', 'System: Import Certificate Profile', 'System: Manage CA ACL Membership', 'System: Manage DNSSEC keys', 'System: Manage DNSSEC metadata', 'System: Manage HBAC Rule Membership', 'System: Manage HBAC Service Group Membership', 'System: Manage Host Certificates', 'System: Manage Host Enrollment Password', 'System: Manage Host Keytab', 'System: Manage Host Keytab Permissions', 'System: Manage Host Principals', 'System: Manage Host Resource Delegation', 'System: Manage Host SSH Public Keys', 'System: Modify Automount Keys', 'System: Modify Automount Maps', 'System: Modify CA', 'System: Modify CA ACL', 'System: Modify Certificate Profile', 'System: Modify Certmap Configuration', 'System: Modify Certmap Rules', 'System: Modify DNS Servers Configuration', 'System: Modify External Group Membership', 'System: Modify External IdP server', 'System: Modify Group Membership', 'System: Modify Group Password Policy costemplate', 'System: Modify Groups', 'System: Modify HBAC Rule', 'System: Modify Hostgroup Membership', 'System: Modify Hostgroups', 'System: Modify Hosts', 'System: Read Automember Definitions', 'System: Read Automember Rules', 'System: Read Automember Tasks', 'System: Read Automount Configuration', 'System: Read CA ACLs', 'System: Read CAs', 'System: Read Certificate Profiles', 'System: Read Certmap Configuration', 'System: Read Certmap Rules', 'System: Read Default Kerberos Ticket Policy', 'System: Read DNS Configuration', 'System: Read DNS Entries', 'System: Read DNS Servers Configuration', 'System: Read DNSSEC metadata', 'System: Read External Group Membership', 'System: Read External IdP server', 'System: Read External IdP server client secret', 'System: Read Global Configuration', 'System: Read Group Compat Tree', 'System: Read Group ID Overrides', 'System: Read Group Membership', 'System: Read Group Password Policy costemplate', 'System: Read Group Views Compat Tree', 'System: Read Groups', 'System: Read HBAC Rules', 'System: Read HBAC Service Groups', 'System: Read HBAC Services', 'System: Read Host Compat Tree', 'System: Read Host Membership', 'System: Read Hostgroup Membership', 'System: Read Hostgroups', 'System: Read Hosts', 'System: Read ID Ranges', 'System: Read ID Views', 'System: Read User ID Overrides', 'System: Remove Automount Keys', 'System: Remove Automount Locations', 'System: Remove Automount Maps', 'System: Remove DNS Entries', 'System: Remove Groups', 'System: Remove Hostgroups', 'System: Remove Hosts', 'System: Update DNS Entries', 'System: Write DNS Configuration'])

        #self.helper('permission', 'cn')


def parse_args():
    parser = argparse.ArgumentParser(
        add_help=True, description='For filling FreeIPA with data',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-u', '--username', action='store', help='Domain admin username')
    parser.add_argument('-k', '--kerberos', action='store_true', help='Use $KRB5CCNAME for auth')
    parser.add_argument('-p', '--password', action='store', help='Domain admin password')
    parser.add_argument('-dc', '--domain-controller', metavar='HOST', action='store', help='DC hostname')
    return parser


def main():
    parser = parse_args()
    args = parser.parse_args()

    if (args.kerberos is False) and (args.username is None or args.password is None or args.domain_controller is None):
        print('Please specify DC, username and password or use $KRB5CCNAME')
        parser.print_help()
        exit(1)
    
    client = BadIPA_cleaner(args.domain_controller, args.username, args.password, kerberos_login=args.kerberos)
    client.clear_all()


if __name__ == '__main__':
    main()
