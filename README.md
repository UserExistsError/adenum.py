# adenum.py
Remote Active Directory enumeration

## Installation
Requires python 3.4 or greater.
```
pip install -r requirements.txt
```

To read the default password policy from the SYSVOL share, you'll need either smbclient or pysmb.


## Examples
NOTE: If your system is not configured to use the name server for the domain, you must specify the domain controller with -s or the domain's name server with --name-server. In nearly all AD domains, the domain controller acts as the name server. Domains specified with -d must be fully qualified.

### List password policies
Non-default policies may require higher privileges.
```
$ adenum.py -u USER -d DOMAIN_FQDN policy
```

### List all users and groups. Use -a for active users only.
```
$ adenum.py -u USER -d DOMAIN_FQDN users
$ adenum.py -u USER -d DOMAIN_FQDN groups
```

### List domain admins
```
$ adenum.py -u USER -d DOMAIN_FQDN group "domain admins"
```

### List domain joined computers.
Add -r and -s to resolve hostnames and run smbinfo. Use -a to report active hosts only
```
$ adenum.py -u USER -d DOMAIN_FQDN computers -r -s
```

### List pre-auth LDAP server information
```
$ adenum.py -s SERVER -i
```

## Query Caching
By default, queries are saved in a temporary sqlite database file which is destroyed on exit. This is used to avoid making the same LDAP query twice and prevents high memory usage. By specifying a db with --session, this database will persist across invocations of adenum.py. To avoid using disk, specify a name of ":memory:" (see https://docs.python.org/3/library/sqlite3.html).

## Resources
All defined AD attributes
```
https://msdn.microsoft.com/en-us/library/ms675090(v=vs.85).aspx
```

## Additional Scripts
Scripts that provide a subset of adenum's capabilities.

### smbinfo.py
Probes targets for SMB versions, uptime, and build information. Accepts nmap XML files.
```
$ smbinfo.py [HOST1 [..HOSTN]] [-f HOSTFILE] [-x nmap-445.xml]
```

### getdc.py
List domain controllers for provided domain.
```
$ getdc.py -d DOMAIN_FQDN
```
