# BlueFish
> ## **_BlueFish is a complete covert application that allows a user to remotely open a port on a firewall, communicate with a “disguised” backdoor._**

In this cloud computing era, more and more companies/individules have created Linux VMs in the cloud and millions of suspicius traffic are targeting the ssh processes running on each VM. Preventing unauthorized ssh access has become the most important job for IT professionals. This is why the Port Knocking technology comes into play.

### Background
A backdoor in a computer system (or cryptosystem/algorithm) is a method of bypassing normal authentication or securing remote access to a computer, while attempting to remain hidden from casual inspection. The backdoor may take the form of an installed program (e.g., Back Orifice), or could be a modification to a legitimate program. This program is using packet sniffing backdoor techniques that have evolved from the need to bypass a local firewall without embedding code or connecting back to an attacker’s machine. It works by capturing packets in which encrypted commands are embedded, and decodes those packets to obtain commands to execute. The packets containing the backdoor commands do not have to be accepted by the system as a part of an established connection; they simply have to be received by the target system’s network interface card. By capturing packets directly from the NIC, and bypassing the TCP/IP stack together, packets are captured by the backdoor regardless of being locally filtered by mechanisms such as Netfilter.

Port knocking is a unique technique that allows remote users to open up a port remotely by sending one or more authentication knocking packets (known as token). Once the server receives the token, it will decrypt and authenticate it with specific algorithm, then open a port for the client specified in the token. After a specified time period, the server will close the port and only allows the established connections to keep working. With port knocking, an association between an IP address and individual user is no longer necessary. The users can identify themselves using their authentication tokens without requiring any ports to be opened on the server. It allows a specific user to connect from any IP, rather than any user to connect from a specific IP.

### Features

#### Server
- Working as a Linux daemon with root privilege. 
- Self-camouflaged and cannot be identified from process table easily. 
- Packets authentication needed. 
- All outputs will be redirected to NULL device. 
- Can accept any kind of Linux commands and execute them covertly. 
- Can be terminated remotely. 
- Sniffing packets in non-promiscuous mode so as to prevent it from showing up in local system logs. 
- Simple Triple-XOR and Triple-DES algorithm are used. (more algorithm will be added later)
- It allows users to send their commands interactively. 
- Client IP has to be authenticated. 
- Information will only be sent to the authenticated IP address, wherever the request packets come from. 
- Parameters will be loaded from a configuration file. 
- Results can be sent back to clients using covert channel. 
- Single packet port knocking and authentication. 
- Firewall rules handling. 
- Support file exfiltration via covert channel. 
- Port knocking is protected by a password which can be changed only on the server side. 
- Uses both libpcap and raw socket to sniff packets at the data link layer 

#### Client
- GTK+ GUI and GThread application for Gnome. (Will move to Qt cross-platform when I have time)
- Sending any command to the server using covert channel
- Downloading files from the server. 
- Sending port knocking packets. 
- Sending IP authentication request packet for itself
- All source IPs can be spoofed except the authentication
- Terminating the server remotely. 
- Parameters are loaded from a configuration file.

### The Protocols
#### UDP + Payload
![image](https://user-images.githubusercontent.com/57880343/152665295-f37131ad-99fd-47d1-a933-d34b3a9c2741.png)

Where: 
```
	IP.SourceAddr = Source address (Can be spoofed) 
	IP.DestAddr = Destination address 
	UDP.SrcPort = Source port (Can be configured) 
	UDP.DetPort = Destination port (Can be configured) 
	Data[0]..Data[3] = 0x55AA (Token 1) 
	Data[60]..Data[63] = 0xAA55 (Token 2) 
	Data[4]..Data[59] = Command (3-xor encrypted) 
```
#### TCP Header 01
![image](https://user-images.githubusercontent.com/57880343/152665378-0426eea2-a08e-491e-adb4-a09ac625a926.png)

Where:
```
	TCP.Seq = Client IP needed to be authenticated (3-DES encrypted) 
	TCP.Ack = Server IP needed to be verified (3-DES encrypted) 
	TCP.SrcPort = Source port for authentication packet (Can be configured) 
	TCP.DstPort = Destination port for authentication packet (Can be configured) 
	TCP.Flags (Only SYN flag set)
```
#### TCP Header 02
![image](https://user-images.githubusercontent.com/57880343/152665414-63fccc12-a6b2-4ff8-af02-9448046e9ecd.png)

Where:
```
	IP.Identification = knock.checksum (3-DES encrypted) 
	IP.SrcAddr = Source Address (Can be spoofed) 
	IP.DstAddr = Destination Address 
	TCP.SrcPort = Source Port (Can be configured) 
	TCP.DstPort = Destination Port (Can be configured) 
	TCP.Window = knock.port (The actual port need to be opened) (3-DES encrypted) 
	TCP.Seq = knock.time (Including start time and how long the port will be opened) (3-DES encrypted) 
	TCP.Ack_Seq = knock.sip (The actual IP address the required port will be opened to) (3-DES encrypted) 
	TCP.res1 = Protocol type (0x1000 = TCP, 0x0010 = UDP, 0x1010 = both TCP + UDP) 
	TCP.Flags (Only SYN flag set) 
```
Explanation of knock struct: 
```C
	struct knock 
	{ 
		 unsigned checksum :16; // For extra checksum 
		 unsigned port :16; // The knocking port number 
		 struct Time // Knocking info 
		 { 
			 unsigned hour : 5; 
			 unsigned minute : 6; 
			 unsigned second : 6; 
			 unsigned dur :15; 
		 } time; 
		 unsigned sip :32; // The port will be opened for this IP only
	};                         // 12 bytes total
```
The checksum is for the whole struct. The client program will firstly fill out this structure with zero checksum, then calculate the checksum and fill it back to the struct. Secondly the structure will be encrypted by 3-des algorithm using the user supplied password and embedded into the TCP header. 

#### ICMP Echo-reply
![image](https://user-images.githubusercontent.com/57880343/152665465-75f65041-6ca1-43bb-a497-ef2d2de366b2.png)

Where:
```
	ICMP.Type = 0 (ICMP Echo-Reply) 
	ICMP.Code = 8 (For screening packets) 
	ICMP.Echo.ID = 0x55AA (For screening packets, can be configured) 
	ICMP.Echo.Seq = To simulate the ping sequence number 
	Data = Command execution results (3-xor encrypted) 
```
#### ICMP Echo
![image](https://user-images.githubusercontent.com/57880343/152665488-ef1c820d-6baf-455b-b1bf-f348cb89dae7.png)

Where:
```
	ICMP.Type = 8 (ICMP Echo) 
	ICMP.Code = Number of bytes actually the
	ICMP.Echo.ID = 0xAA55 (For screening packets
	ICMP.Echo.Seq = Simulating the ping sequence
	Data = File contents (3-xor encrypted) 
```
### State Transition Diagram
#### Server
![image](https://user-images.githubusercontent.com/57880343/152665567-d518a1e1-c251-48d9-b9c8-8376270fa437.png)
#### Client
![image](https://user-images.githubusercontent.com/57880343/152665577-1b7caf5f-efbe-4a7e-ad40-9b4cf9606474.png)

### Screenshots
![image](https://user-images.githubusercontent.com/57880343/152665662-c5d56845-38b0-4d04-a3dc-2ffd310cb09b.png)
![image](https://user-images.githubusercontent.com/57880343/152665672-1589c598-f135-41f6-b6ba-c27e3134f7db.png)
![image](https://user-images.githubusercontent.com/57880343/152665683-ab82dad5-23ed-4df6-86d0-143c90a734f5.png)
![image](https://user-images.githubusercontent.com/57880343/152665700-6fd7e293-ce72-46d0-bd75-8479998bc4bd.png)
![image](https://user-images.githubusercontent.com/57880343/152665711-9a5fc27b-ebda-4bb6-b769-73bcb75df7f9.png)

![image](https://user-images.githubusercontent.com/57880343/152666181-f28f2b4e-5210-48d3-b5c9-61ea41f64ce4.png)

> ## **_Please DO NOT use this program in an production environment as the 3-DES and 3-XOR encryption algorithm is not strong enough to protect your token. I will add AES256/512 or RSA later to make it more secure._**
![](https://komarev.com/ghpvc/?username=MeCRO-DEV&color=green)
