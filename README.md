# adenum.py
Remote Active Directory enumeration

## Installation

```
pip3 install -r requirements.txt
```

To read the default password policy from the SYSVOL share, you'll need either smbclient or pysmb.


## Examples
NOTE: If your system is not configured to use the name server for
the domain, you must specify the domain controller with -s or the
domain's name server with --name-server. In nearly all AD domains,
the domain controller acts as the name server. Domains specified
with -d must be fully qualified.

### List password policies
Non-default policies may require higher privileges.
```
$ python3 adenum.py -u USER -P -d mydomain.local policy
```

### List all users and groups
```
$ python3 adenum.py -u USER -P -d mydomain.local users
$ python3 adenum.py -u USER -P -d mydomain.local groups
```

### List domain admins
```
$ python3 adenum.py -u USER -P -d mydomain.local group "domain admins"
```

### List domain joined computers.
Add -r and -s to resolve hostnames and run smbinfo. Use --alive to report active hosts only
```
$ python3 adenum.py -u USER -P -d mydomain.local computers -r -s
```

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
$ python3 smbinfo.py -a [HOST1 [..HOSTN]] [-f HOSTFILE] [-x nmap-445.xml]
```

### getdc.py
List domain controllers for provided domain.
```
$ python3 getdc.py -d mydomain.local
```
