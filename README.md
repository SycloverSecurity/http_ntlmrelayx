# HTTP_NTLMRELAYX

A Metasploit module for http->smb relay/reflection.
Avoid some bugs in impacket, and add features not available in the same type of msf modules.

### Author

----
Exist

### Installation

------

Drop it in the exploit module directory, for example,  `exploit/windows/smb/`

### How to use it?

----


```
set rhosts 192.168.1.1
set rport 445
set rtype SMB_AUTOPWN
set ruripath  c$\\windows
run
```

#### Optional settings
* **SMB_VERSION** - Although this module will automatically detect the smb version on the target, sometimes you want to specify it manually. For example, if the target supports both v1 and v2,  this module uses v2 by default, but you need to use v1 for some reason, just input `set SMB_VERSION 1`.
* **HOSTNAME** - Specify the target host netbios name. The module will extract the target name from the negotiation response, but the code may not be rigorous, so it may go wrong. See the **Troubleshooting** section for more details.

### Features

-----
* SMBv1 and SMBv2 support
* Automatically get meterpreter - upload meterpreter->create service->start service

### Troubleshooting

-----

1. `STATUS_DUPLICATE_NAME` && `STATUS_BAD_NETWORK_NAME`
This is usually because of an error or a mismatched netbios name. Setting the correct `hostname` usually solves this problem. type `set hostname abcd`.
2. `STATUS_ACCESS_DENIED`
First you need to determine if you have permission to write to share and call scm function. After vista, UAC also restricted network authentication, which means that not all members of the administrator group can access c\$ and admin\$, and the built-in administrator (rid is 500) is not restricted.
Another possibility is that the smb service has enabled the smb signature. The server does not block the login, but subsequent writes will return `STATUS_ACCESS_DENIED` status code.

### Known issues

-----
* When calling scm to create service,  service response interval may exceed expected time, module may throw an exception(Maybe relate to STATUS_PENDING).

### Tested
**OS**
* Windows Server 2012 R2 SP1 

**Application**
* Java SSRF(with CVE-2019-2426)
* Exchange SSRF(with CVE-2018-8581)

### TODO

-----

- [ ] More services for relay/reflection(DCOM, Exchange, ...)
- [ ] More command execution methods(atsvc, winreg, ...)
