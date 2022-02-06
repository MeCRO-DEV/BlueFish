# BlueFish
> ## **_BlueFish is a complete covert application that allows a user to open a port on a firewall, communicate with a “disguised” backdoor._**

In this cloud computing era, more and more companies/individules have created Linux VMs in the cloud and millions of suspicius traffic are targeting the ssh processes running on each VM. Preventing unauthorized ssh access has become the most important job for IT professionals. This is why the Port Knocking technology comes into play.

### Background
A backdoor in a computer system (or cryptosystem/algorithm) is a method of bypassing normal authentication or securing remote access to a computer, while attempting to remain hidden from casual inspection. The backdoor may take the form of an installed program (e.g., Back Orifice), or could be a modification to a legitimate program. This program is using packet sniffing backdoor techniques that have evolved from the need to bypass a local firewall without embedding code or connecting back to an attacker’s machine. It works by capturing packets in which encrypted commands are embedded, and decodes those packets to obtain commands to execute. The packets containing the backdoor commands do not have to be accepted by the system as a part of an established connection; they simply have to be received by the target system’s network interface card. By capturing packets directly from the NIC, and bypassing the TCP/IP stack together, packets are captured by the backdoor regardless of being locally filtered by mechanisms such as Netfilter.

Port knocking is a unique technique that allows remote users to open up a port remotely by sending one or more authentication knocking packets (known as token). Once the server receives the token, it will decrypt and authenticate it with specific algorithm, then open a port for the client specified in the token. After a specified time period, the server will close the port and only allows the established connections to keep working. With port knocking, an association between an IP address and individual user is no longer necessary. The users can identify themselves using their authentication tokens without requiring any ports to be opened on the server. It allows a specific user to connect from any IP, rather than any user to connect from a specific IP.

### Features

#### Server
 Working as a Linux daemon with root privilege. 
 Self-camouflaged and cannot be identified from process table easily. 
 Packets authentication needed. 
 All outputs will be redirected to NULL device. 
 Can accept any kind of Linux commands and execute them covertly. 
 Can be terminated remotely. 
 Sniffing packets in non-promiscuous mode so as to prevent it from showing up in local system logs. 
 Simple Triple-XOR and Triple-DES algorithm are used. 
 It allows users to send their commands interactively. 
 Client IP has to be authenticated. 
 Information will only be sent to the authenticated IP address, where ever the request packets come from. 
 Parameters will be loaded from a configuration file. 
 Results can be sent back to clients using covert channel. 
 Single packet port knocking and authentication. 
 Firewall rules handling. 
 Support file exfiltration via covert channel. 
 Port knocking is protected by a password which can be changed only on the server side. 
 Uses both libpcap and raw socket to sniff packets at the data link layer 

![](https://komarev.com/ghpvc/?username=MeCRO-DEV&color=green)
