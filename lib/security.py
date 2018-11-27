def get_ldap_control():
    ''' https://msdn.microsoft.com/en-us/library/cc223323.aspx
    security descriptor control. ignores SACL which requires admin '''
    return ('3.1.1.3.4.1.11', False, 7)

class ACE:
    type_names = {
        'A':'SDDL_ACCESS_ALLOWED',
        'D':'SDDL_ACCESS_DENIED',
        'OA':'SDDL_OBJECT_ACCESS_ALLOWED',
        'OD':'SDDL_OBJECT_ACCESS_DENIED',
        'AU':'SDDL_AUDIT',
        'AL':'SDDL_ALARM:',
        'OU':'SDDL_OBJECT_AUDIT',
        'OL':'SDDL_OBJECT_ALARM',
        'ML':'SDDL_MANDATORY_LABEL',
        'XA':'SDDL_CALLBACK_ACCESS_ALLOWED',
        'XD':'SDDL_CALLBACK_ACCESS_DENIED',
        'RA':'SDDL_RESOURCE_ATTRIBUTE',
        'SP':'SDDL_SCOPED_POLICY_ID',
        'XU':'SDDL_CALLBACK_AUDIT',
        'ZA':'SDDL_CALLBACK_OBJECT_ACCESS_ALLOWED',
    }
    right_names = {
        'GA':'GENERIC_ALL',
        'GR':'GENERIC_READ',
        'GW':'GENERIC_WRITE',
        'GX':'GENERIC_EXECUTE',
        'RC':'READ_CONTROL',
        'SD':'DELETE',
        'WD':'WRITE_DAC',
        'WO':'WRITE_OWNER',
        'RP':'ADS_RIGHT_DS_READ_PROP',
        'WP':'ADS_RIGHT_DS_WRITE_PROP',
        'CC':'ADS_RIGHT_DS_CREATE_CHILD',
        'DC':'ADS_RIGHT_DS_DELETE_CHILD',
        'LC':'ADS_RIGHT_ACTRL_DS_LIST',
        'SW':'ADS_RIGHT_DS_SELF',
        'LO':'ADS_RIGHT_DS_LIST_OBJECT',
        'DT':'ADS_RIGHT_DS_DELETE_TREE',
        'CR':'ADS_RIGHT_DS_CONTROL_ACCESS',
        'FA':'FILE_ALL_ACCESS',
        'FR':'FILE_GENERIC_READ',
        'FW':'FILE_GENERIC_WRITE',
        'FX':'FILE_GENERIC_EXECUTE',
        'KA':'KEY_ALL_ACCESS',
        'KR':'KEY_READ',
        'KW':'KEY_WRITE',
        'KX':'KEY_EXECUTE',
        'NR':'SYSTEM_MANDATORY_LABEL_NO_READ_UP',
        'NW':'SYSTEM_MANDATORY_LABEL_NO_WRITE_UP',
        'NX':'SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP',
    }
    sid_constants_sddl = {
        # see Sddl.h in the SDK
        'AN':'SDDL_ANONYMOUS',
        'AO':'SDDL_ACCOUNT_OPERATORS',
        'AU':'SDDL_AUTHENTICATED_USERS',
        'BA':'SDDL_BUILTIN_ADMINISTRATORS',
        'BG':'SDDL_BUILTIN_GUESTS',
        'BO':'SDDL_BACKUP_OPERATORS',
        'BU':'SDDL_BUILTIN_USERS',
        'CA':'SDDL_CERT_SERV_ADMINISTRATORS',
        'CD':'SDDL_CERTSVC_DCOM_ACCESS',
        'CG':'SDDL_CREATOR_GROUP',
        'CO':'SDDL_CREATOR_OWNER',
        'DA':'SDDL_DOMAIN_ADMINISTRATORS',
        'DC':'SDDL_DOMAIN_COMPUTERS',
        'DD':'SDDL_DOMAIN_DOMAIN_CONTROLLERS',
        'DG':'SDDL_DOMAIN_GUESTS',
        'DU':'SDDL_DOMAIN_USERS',
        'EA':'SDDL_ENTERPRISE_ADMINS',
        'ED':'SDDL_ENTERPRISE_DOMAIN_CONTROLLERS',
        'HI':'SDDL_ML_HIGH',
        'IU':'SDDL_INTERACTIVE',
        'LA':'SDDL_LOCAL_ADMIN',
        'LG':'SDDL_LOCAL_GUEST',
        'LS':'SDDL_LOCAL_SERVICE',
        'LW':'SDDL_ML_LOW',
        'ME':'SDDL_MLMEDIUM',
        'MU':'SDDL_PERFMON_USERS',
        'NO':'SDDL_NETWORK_CONFIGURATION_OPS',
        'NS':'SDDL_NETWORK_SERVICE',
        'NU':'SDDL_NETWORK',
        'PA':'SDDL_GROUP_POLICY_ADMINS',
        'PO':'SDDL_PRINTER_OPERATORS',
        'PS':'SDDL_PERSONAL_SELF',
        'PU':'SDDL_POWER_USERS',
        'RC':'SDDL_RESTRICTED_CODE',
        'RD':'SDDL_REMOTE_DESKTOP',
        'RE':'SDDL_REPLICATOR',
        'RO':'SDDL_ENTERPRISE_RO_DCs',
        'RS':'SDDL_RAS_SERVERS',
        'RU':'SDDL_ALIAS_PREW2KCOMPACC',
        'SA':'SDDL_SCHEMA_ADMINISTRATORS',
        'SI':'SDDL_ML_SYSTEM',
        'SO':'SDDL_SERVER_OPERATORS',
        'SU':'SDDL_SERVICE',
        'SY':'SDDL_LOCAL_SYSTEM',
        'WD':'SDDL_EVERYONE'
    }
    rid_constants = {
        'AN':[7, 'Anonymous Logon'],
        'AO':[548, 'Account Ops'],
        'AU':[11, 'Authenticated User'],
        'BA':[544, 'Admins'],
        'BG':[546, 'Guests'],
        'BO':[551, 'Backup Ops'],
        'BU':[545, 'Users'],
        'CA':[517, 'Cert Admins'],
        'CD':[574, 'Certsvc Dcom Access Group'],
        'CG':[1, 'Creator Group'],
        'CO':[0, 'Creator Owner'],
        'DA':[512, 'Domain Admins'],
        'DC':[515, 'Computers'],
        'DD':[516, 'Controllers'],
        'DG':[514, 'Guests'],
        'DU':[513, 'Users'],
        'EA':[519, 'Enterprise Admins'],
        'HI':[12288, 'Mandatory High'],
        'IU':[4, 'Interactive'],
        'LA':[500, 'Admin'],
        'LG':[501, 'Guest'],
        'LS':[19, 'Local Service'],
        'LW':[4096, 'Mandatory Low'],
        'ME':[8192, 'Mandatory Medium'],
        'NO':[556, 'Network Configuration Ops'],
        'NS':[20, 'Network Service'],
        'NU':[2, 'Network'],
        'PA':[520, 'Policy Admins'],
        'PO':[550, 'Print Ops'],
        'PS':[10, 'Principal Self'],
        'PU':[547, 'Power Users'],
        'RC':[12, 'Restricted Code'],
        'RD':[555, 'Remote Desktop Users'],
        'RE':[552, 'Replicator'],
        'RO':[498, 'Enterprise Readonly Domain Controllers'],
        'RS':[553, 'Ras Servers'],
        'RU':[554, 'Prew2Kcompaccess'],
        'SA':[518, 'Schema Admins'],
        'SI':[16384, 'Mandatory System'],
        'SO':[549, 'System Ops'],
        'SU':[6, 'Service'],
        'SY':[18, 'Local System'],
        'WD':[0, 'World'],
    }
    def __init__(self, s):
        '''
        ACE format: https://docs.microsoft.com/en-us/windows/desktop/SecAuthZ/ace-strings
        well known SID constants: https://docs.microsoft.com/en-us/windows/desktop/SecAuthZ/sid-strings
        '''
        f = s.split(';')
        self.ace_type = f[0]
        self.ace_flags = f[1]
        self.rights = [f[2][i:i+2] for i in range(0, len(f[2]), 2)]
        self.object_guid = f[3].lower()
        self.inherit_object_guid = f[4].lower()
        self.account_sid = f[5]
        self.resource_attribute = f[6] if len(f) == 7 else None
    def dump(self):
        s =  '[ACE]\n'
        s += '    Type         {}\n'.format(ACE.type_names[self.ace_type])
        s += '    Flags        {}\n'.format(self.ace_flags)
        s += '    Rights       {}\n'.format(','.join([ACE.right_names[r] for r in self.rights]))
        s += '    GUID         {}\n'.format(self.object_guid)
        s += '    IGUID        {}\n'.format(self.inherit_object_guid)
        if self.account_sid in ACE.rid_constants:
            s += '    AccountSID   {} ({})\n'.format(ACE.rid_constants[self.account_sid][0],
                                                     ACE.rid_constants[self.account_sid][1])
        else:
            s += '    AccountSID   {}\n'.format(self.account_sid)
        s += '    ResourceAttr {}\n'.format(self.resource_attribute or '')
        return s

class ACL:
    flag_abbv_map = {
        'P':'PROTECTED',
        'AR':'AUTO_INHERIT_REQ',
        'AI':'AUTO_INHERIT',
        'NO_ACCESS_CONTROL':'NULL_ACL',
    }
    def __init__(self, s):
        # ref: https://docs.microsoft.com/en-us/windows/desktop/SecAuthZ/dacls-and-aces
        self.flags = None
        self.aces = []
        self.parse_acl(s)
    def parse_acl(self, a):
        self.flags, a = a.split('(', maxsplit=1)
        for ace in a.split('('):
            self.aces.append(ACE(ace.strip('()\n')))
    def dump(self):
        s = 'Flags {}\n'.format(self.flags)
        for a in self.aces:
            s += a.dump()
        return s

class DACL(ACL):
    pass

class SACL(ACL):
    pass

class SecurityDescriptor:
    def __init__(self, s):
        ''' accepts security descriptor string as retrieved from LDAP:
        https://docs.microsoft.com/en-us/windows/desktop/SecAuthZ/security-descriptor-string-format '''
        self.owner_sid = None
        self.group_sid = None
        self.dacl = None
        self.sacl = None
        self.parse_security_descriptor(s)
    def parse_security_descriptor(self, d):
        for p in d.split(','):
            if p[0] == 'O':
                self.owner_sid = p.split(':', maxsplit=1)[1]
            elif p[0] == 'G':
                self.group_sid = p.split(':', maxsplit=1)[1]
            elif p[0] == 'D':
                self.dacl = DACL(p.split(':', maxsplit=1)[1])
            elif p[0] == 'S':
                self.sacl = SACL(p.split(':', maxsplit=1)[1])
    def dump(self):
        s =  '[SecurityDescriptor]\n'
        s += '    OwnerSID {}\n'.format(self.owner_sid)
        s += '    GroupSID {}\n'.format(self.group_sid)
        if self.dacl:
            s += 'DACL\n'
            s += self.dacl.dump()
        if self.sacl:
            s += 'SACL\n'
            s += self.sacl.dump()
        return s
