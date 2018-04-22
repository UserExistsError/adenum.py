# scripts
Scripts for enumerating Windows networks. 

## Installation

```
pip2 install -r requirements.txt
```

### smblogin2.py
Uses impacket to test credentials and check for access to ADMIN$ share.
```
$ python2 smblogin2.py -u USERNAME -p PASSWORD [-w THREADS] [-d DOMAIN] [-f HOSTFILE] [HOST1 [..HOSTN]]
```

### userenum2.py
Enumerate logged in users on given hosts using MSRPC over SMB. The Win32 API is NetWkstaUserEnum.
```
$ python2 userenum2.py -u USERNAME -p PASSWORD [-w THREADS] [-d DOMAIN] [-f HOSTFILE] [HOST1 [..HOSTN]]
```
