from python_freeipa import ClientMeta
import random
import os
from python_freeipa import exceptions as ipa_exceptions


class BadIPA_API(object):
    def __init__(self, dc, username, password, logger, verify_ssl=False, verbose=False, size=400, kerberos_login=False):
        self.logger = logger
        self.size = int(size)
        self.verbose = verbose
        self.dc = dc

        self.group_size = 10

        self.users = []
        self.hosts = []
        self.services = []

        self.groups = []
        self.netgroups = []
        self.hostgroups = []

        self.sudocmdgroups = []
        self.sudorules = []

        self.roles = []

        self.domain = '.'.join(self.dc.split('.')[1:]).lower()
        if not kerberos_login:
            self.auth(username, password, verify_ssl)
        else:
            self.kerberos_auth()


    def auth(self, username, password, verify_ssl):
        # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client.Client.login
        self.logger.debug('Authentication: username/password')
        self.client = ClientMeta(self.dc, verify_ssl=verify_ssl)
        self.client.login(username, password)


    def kerberos_auth(self):
        # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client.Client.login_kerberos
        self.logger.debug('Authentication: $KRB5CCNAME')
        try:
            self.client.login_kerberos()
        except ipa_exceptions.Unauthorized as error:
            self.logger.error('An exception occurred:', error)
            exit(1)


    def add_users(self):
        self.logger.info(f'Adding {self.size} users...')
        for i in range(self.size):
            # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.user_add
            user_uid = os.urandom(8).hex()
            try:
                user = self.client.user_add(
                    #a_uid=user_uid, o_givenname=names[i], o_sn=surnames[i], o_cn=names[i]+' '+surnames[i],
                    a_uid=user_uid, o_givenname=user_uid[:8], o_sn=user_uid[8:], o_cn=user_uid[:8]+' '+user_uid[8:],
                    o_random=True, o_mail=user_uid+'@'+self.domain)
            except ipa_exceptions.DuplicateEntry:
                pass
            self.users.append(user['result']['uid'])
            self.logger.debug(f'uid: {user["result"]["uid"]}; randompassword: {user["result"]["randompassword"]}')
            user_group = random.choice(self.groups)
            # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.group_add_member
            self.client.group_add_member(a_cn=user_group, o_user=user["result"]["uid"])
            self.logger.debug(f'User {user["result"]["uid"]} is member of {user_group}')
            if random.randint(0, 3) == 0:
                net_group = random.choice(self.netgroups)
                self.client.netgroup_add_member(a_cn=net_group, o_user=user["result"]["uid"])
                self.logger.debug(f'User {user["result"]["uid"]} is member of {net_group}')
        self.logger.info(f'Adding users done')


    def add_hosts(self):
        # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.host_add
        self.logger.info(f'Adding {self.size} hosts...')
        for i in range(self.size):
            fqdn = os.urandom(6).hex()
            host_uid = f'WS-{fqdn}.{self.domain}'
            self.hosts.append(host_uid)
            self.client.host_add(a_fqdn=host_uid, o_description=f'{fqdn}', o_no_reverse=True, o_force=True)
            # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.hostgroup_add_member
            host_group = random.choice(self.hostgroups)
            self.client.hostgroup_add_member(a_cn=host_group, o_host=host_uid)
            self.logger.debug(f'Host {host_uid} is member of {host_group}')
            if random.randint(0, 3) == 0:
                net_group = random.choice(self.netgroups)
                self.client.netgroup_add_member(a_cn=net_group, o_host=host_uid)
                self.logger.debug(f'Host {host_uid} is member of {net_group}')
        self.logger.info(f'Adding hosts done')


    def add_groups(self):
        # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.group_add
        self.logger.info(f'Adding {self.group_size} groups...')
        for i in range(self.group_size):
            cn = f'{os.urandom(6).hex()}_group'
            self.client.group_add(a_cn=cn)
            self.groups.append(cn)
        self.logger.info(f'Adding groups done')


    def add_hostgroups(self):
        # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.hostgroup_add
        self.logger.info(f'Adding {self.group_size} hostgroups...')
        for i in range(self.group_size):
            cn = f'{os.urandom(6).hex()}_hostgroup'
            self.client.hostgroup_add(a_cn=cn)
            self.hostgroups.append(cn)
        self.logger.info(f'Adding hostgroups done')


    def add_netgroups(self):
        # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.netgroup_add
        self.logger.info(f'Adding {self.group_size} netgroups...')
        for i in range(self.group_size):
            cn = f'{os.urandom(6).hex()}_netgroup'
            self.client.netgroup_add(a_cn=cn)
            self.netgroups.append(cn)
        self.logger.info(f'Adding netgroups done')


    def add_groups_to_groups(self):
        # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.group_add_member
        self.logger.info('Adding groups to groups...')
        for group in self.groups:
            if random.randint(0, 3) == 0:
                user_group = random.choice(self.groups)
                if user_group != group:
                    self.client.group_add_member(a_cn=user_group, o_group=group)
                    self.logger.debug(f'Group {group} is member of {user_group} group')
                if random.randint(0, 4) == 0:
                    net_group = random.choice(self.netgroups)
                    self.client.netgroup_add_member(a_cn=net_group, o_group=group)
                    self.logger.debug(f'Group {group} is member of {net_group} netgroup')
        for hostgroup in self.hostgroups:
            if random.randint(0, 3) == 0:
                host_group = random.choice(self.hostgroups)
                if host_group != hostgroup:
                    self.client.hostgroup_add_member(a_cn=host_group, o_hostgroup=hostgroup)
                    self.logger.debug(f'Hostgroup {hostgroup} is member of {host_group} hostgroup')
            if random.randint(0, 4) == 0:
                net_group = random.choice(self.netgroups)
                self.client.netgroup_add_member(a_cn=net_group, o_hostgroup=hostgroup)
                self.logger.debug(f'Hostgroup {hostgroup} is member of {net_group} netgroup')
        for netgroup in self.netgroups:
            if random.randint(0, 3) == 0:
                net_group = random.choice(self.netgroups)
                if net_group != netgroup:
                    self.client.netgroup_add_member(a_cn=net_group, o_netgroup=netgroup)
                    self.logger.debug(f'Netgroup {netgroup} is member of {net_group} netgroup')
        self.logger.info('Adding groups to groups done')


    def add_sudocmd_group(self):
        # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.sudocmdgroup_add
        self.logger.info(f'Adding {self.group_size} sudocmdgroups...')
        for i in range(self.group_size):
            cn = f'{os.urandom(6).hex()} sudocmdgroup'
            self.client.sudocmdgroup_add(a_cn=cn)
            self.sudocmdgroups.append(cn)
        self.logger.info(f'Adding sudocmdgroups done')


    def add_sudo_cmd(self, commands):
        # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.sudocmd_add
        self.logger.info(f'Adding {len(commands)} sudocmds...')
        for command in commands:
            self.client.sudocmd_add(a_sudocmd=command)
            sudo_group = random.choice(self.sudocmdgroups)
            self.client.sudocmdgroup_add_member(a_cn=sudo_group, o_sudocmd=command)
            self.logger.debug(f'Sudocmd {command} is member of {sudo_group} sudocmdgroup')
        self.logger.info(f'Adding sudocmds done')


    def add_sudo_rules(self):
        # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.sudorule_add
        self.logger.info(f'Adding {self.group_size} sudorules...')
        for i in range(self.group_size):
            sudo_rule = f'{os.urandom(6).hex()} sudorule'
            self.sudorules.append(sudo_rule)
            self.client.sudorule_add(a_cn=sudo_rule)
            group = random.choice(self.groups)
            host_group = random.choice(self.hostgroups)
            self.client.sudorule_add_user(a_cn=sudo_rule, o_group=group)
            self.client.sudorule_add_host(a_cn=sudo_rule, o_hostgroup=host_group)
            if random.randint(0, 3) == 0:
                self.client.sudorule_add_runasuser(a_cn=sudo_rule, o_user='admin')
        self.logger.info(f'Adding sudorules done')


    def add_sudo_hosts(self):
        self.logger.info(f'Adding {len(self.hosts)} sudorule hosts...')
        # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.sudorule_add_host
        for host in self.hosts:
            sudo_rule = random.choice(self.sudorules)
            self.client.sudorule_add_host(a_cn=sudo_rule, o_host=host)
            user = random.choice(self.users)
            # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.sudorule_add_user
            self.client.sudorule_add_user(a_cn=sudo_rule, o_user=user)
        self.logger.info(f'Adding sudorule hosts done')


    def add_sudo_command(self, commands):
        self.logger.info(f'Adding sudorule allows...')
        for sudorule in self.sudorules:
            for command in commands:
                if random.randint(0, 1) == 1:
                    # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.sudorule_add_allow_command
                    self.client.sudorule_add_allow_command(a_cn=sudorule, o_sudocmd=command)
                else:
                    # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.sudorule_add_deny_command
                    self.client.sudorule_add_deny_command(a_cn=sudorule, o_sudocmd=command)
        self.logger.info(f'Adding sudorule allows done')


    def add_roles(self):
        self.logger.info(f'Adding {self.group_size} roles...')
        for i in range(self.group_size):
            # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.role_add
            rolename = f'{os.urandom(6).hex()}_role'
            self.client.role_add(a_cn=rolename)
            self.roles.append(rolename)
            if random.randint(0, 1) == 1:
                # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.role_add_member
                user = random.choice(self.users)
                self.client.role_add_member(a_cn=rolename)
        self.logger.info(f'Adding roles done')


    def add_role_members(self):
        self.logger.info(f'Adding members to roles...')
        for user in self.users:
            # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.role_add_member
            role = random.choice(self.roles)
            self.client.role_add_member(a_cn=role, o_user=user)
        for host in self.hosts:
            # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.role_add_member
            role = random.choice(self.roles)
            self.client.role_add_member(a_cn=role, o_host=host)
        for service in self.services:
            # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.role_add_member
            role = random.choice(self.roles)
            self.client.role_add_member(a_cn=role, o_service=service)
        self.logger.info(f'Adding members to roles done')


    def add_permissions_and_privileges(self):
        self.logger.info(f'Adding permissions and privileges...')
        rights = ['read', 'search', 'compare', 'write', 'add', 'delete', 'all']
        for i in range(self.group_size):
            right = random.choice(rights)
            permission = f'{right}-{os.urandom(6).hex()}-permission'
            privilege = f'{right}-{os.urandom(6).hex()}-privilege'
            target = random.choice(self.groups)
            # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.privilege_add
            self.client.privilege_add(a_cn=privilege)
            # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.permission_add
            self.client.permission_add(a_cn=permission, o_ipapermright=right, o_targetgroup=target)
            # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.privilege_add_permission
            self.client.privilege_add_permission(a_cn=privilege, o_permission=permission)
            role = random.choice(self.roles)
            # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.privilege_add_member
            self.client.privilege_add_member(a_cn=privilege, o_role=role)
        self.logger.info(f'Adding permissions and privileges done')


    def add_services(self, services):
        # https://python-freeipa.readthedocs.io/en/latest/#python_freeipa.client_meta.ClientMeta.service_add
        self.logger.info(f'Adding {len(services)} services...')
        for service in services:
            host = random.choice(self.hosts)
            service_name = f'{service}/{host}.{self.domain}@{self.domain.upper()}'
            self.client.service_add(a_krbcanonicalname=service_name, o_force=True, o_skip_host_check=True)
            self.services.append(service_name)
        self.logger.info(f'Adding services done')


    def add_hbac(self):
        self.logger.info(f'Adding {len(self.hosts)} hbacrules...')
        for host in self.hosts:
            if random.randint(0, 1) == 1:
                hbacrule = f'{host}_allow'
                self.client.hbacrule_add(a_cn=hbacrule, o_accessruletype='allow')
                self.client.hbacrule_add_host(a_cn=hbacrule, o_host=host)
                user = random.choice(self.users)
                self.client.hbacrule_add_user(a_cn=hbacrule, o_user=user)
                self.client.hbacrule_add_user(a_cn=hbacrule, o_group='Administrators')
        self.logger.info(f'Adding hbacrule done')
