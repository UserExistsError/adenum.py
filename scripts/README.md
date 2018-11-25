# scripts
Scripts for enumerating Windows networks. Script names with a '2' use python2/impacket.

## Installation

```
pip2 install -r requirements2.txt
pip install -r requirements.txt
```

## smblogin2.py
Uses impacket to test credentials and check for access to ADMIN$ share.
```
$ smblogin2.py -u USERNAME -p PASSWORD [-w THREADS] [-d DOMAIN] [-f HOSTFILE] [HOST1 [..HOSTN]]
```

## krblogin2.py
Use impacket to test credentials using kerberos.
```
$ krblogin2.py -u USERNAME -p PASSWORD -d DOMAIN DC
```

## userenum2.py
Enumerate logged in users on given hosts using MSRPC over SMB. The Win32 API is NetWkstaUserEnum.
```
$ userenum2.py -u USERNAME -p PASSWORD [-w THREADS] [-d DOMAIN] [-f HOSTFILE] [HOST1 [..HOSTN]]
```

## enumshares.py
Crawl SMB shares and print full path to each file.
```
$ enumshares.py -u USERNAME -p PASSWORD [-w THREADS] [-d DOMAIN] [-f HOSTFILE] [HOST1 [..HOSTN]]
```

## smbget.py
Takes a UNC path as reported by enumshares.py and retrieves the file.
```
$ smbget.py -u USERNAME -p PASSWORD [-d DOMAIN] [-f UNCFILE] [UNC1 [..UNC2]]
```
