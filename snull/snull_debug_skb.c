#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h> /* printk() */
#include <linux/skbuff.h>
#include <linux/ip.h>          /* struct iphdr */
#include <linux/tcp.h>         /* struct tcphdr */

#define MAC(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[4], \
	((unsigned char *)&addr)[5]

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"

#define IPv4(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#define IPv4_FMT "%u.%u.%u.%u"


static void snull_dump_skb_info (const struct sk_buff *skb, char *caption)
{
	trace_printk("---------> %s <--------- \n", caption);
	trace_printk( "\nPrinting SKB info:\n ");

	trace_printk("\n");
	trace_printk( "skb at %p with %d users\n", skb, atomic_read(&skb->users));
	trace_printk( "next          : %p\n",   skb->next);
	trace_printk( "prev          : %p\n",   skb->prev);
	trace_printk( "prev->next    : %p\n",   skb->prev ? skb->prev->next : NULL);
	trace_printk( "next->prev    : %p\n",   skb->next ? skb->next->prev : NULL);
	trace_printk( "dev.name      : %s\n",   skb->dev->name);
	trace_printk( "len           : %d\n",   skb->len);
	trace_printk( "data_len      : %d\n",   skb->data_len);
	trace_printk( "mac_len       : %d\n",   skb->mac_len);
	trace_printk( "hdr_len       : %d\n",   skb->hdr_len);
	trace_printk( "priority      : %d\n",   skb->priority);
	trace_printk( "protocol      : %d\n",   skb->protocol);
	trace_printk( "tstamp.tv64   : %llu\n", skb->tstamp.tv64);

	trace_printk("\n");
	trace_printk( "head          : %p\n", skb->head);
	trace_printk( "data          : %p\n", skb->data);
	trace_printk( "tail          : %#x\n", skb->tail);
	trace_printk( "end           : %#x\n", skb->end);

	trace_printk("\n");
	trace_printk( "tail pointer  : %p\n", skb_tail_pointer(skb));
	trace_printk( "end pointer   : %p\n", skb_end_pointer(skb));
	trace_printk( "headroom      : %d\n", skb_headroom(skb));
	trace_printk( "tailroom      : %d\n", skb_tailroom(skb));

	trace_printk("\n");
	trace_printk( "linear        : %s\n", skb_is_nonlinear(skb) ? "No" : "Yes");
	trace_printk( "FLAGS\n");
	trace_printk( "cloned        : %d\n", skb->cloned);
	trace_printk( "ip_summed     : %d\n", skb->ip_summed);
	trace_printk( "nohdr         : %d\n", skb->nohdr);
	trace_printk( "peeked        : %d\n", skb->peeked);
	trace_printk( "nfctinfo      : %d\n", skb->nfctinfo);
	trace_printk( "pkt_type      : %d\n", skb->pkt_type);
	trace_printk( "fclone        : %d\n", skb->fclone);
	trace_printk( "ipvs_property : %d\n", skb->ipvs_property);

	trace_printk("\n");
	trace_printk( "shared info   : %p \n", skb_shinfo(skb));
	trace_printk( "dataref       : %#x\n", atomic_read(&skb_shinfo(skb)->dataref));
	trace_printk( "frag_list     : %p \n", skb_shinfo(skb)->frag_list);

	trace_printk("\n");
	trace_printk( "skb_mac_header()       : %p\n", skb_mac_header(skb));
	trace_printk( "skb_network_header()   : %p\n", skb_network_header(skb));
	trace_printk( "skb_transport_header() : %p\n", skb_transport_header(skb));
}

static void snull_dump_ethh (struct ethhdr *ethh, char *caption)
{

	trace_printk("---------> %s <--------- \n", caption);
	trace_printk( "\nPrinting Ethernet header info:\n");

	if (ethh) {
		trace_printk( "ethh   : %p\n", ethh);
		trace_printk( "saddr  : "MAC_FMT"\n", MAC(ethh->h_source));
		trace_printk( "daddr  : "MAC_FMT"\n", MAC(ethh->h_dest));
		trace_printk( "proto  : %u\n", ntohs(ethh->h_proto));
	} else
		trace_printk(KERN_ERR "skb: eth header not present\n");
}

static void snull_dump_ip (struct iphdr *iph, char *caption)
{
	char *ps = "unknown";

	trace_printk("---------> %s <--------- \n", caption);
	trace_printk( "\nPrinting IP header info:\n");

	trace_printk( "ihl            : %d\n", iph->ihl);
	trace_printk( "version        : %d\n", iph->version);
	trace_printk( "tos            : %d\n", iph->tos);
	trace_printk( "tot_len        : %d\n", ntohs(iph->tot_len));
	trace_printk( "id             : %d\n", ntohs(iph->id));
	trace_printk( "frag_off       : %d\n", ntohs(iph->frag_off));
	trace_printk( "ttl            : %d\n", iph->ttl);
	trace_printk( "protocol       : %d\n", iph->protocol);
	trace_printk( "check          : %#x\n", ntohs(iph->check));
	trace_printk( "saddr          : "IPv4_FMT"\n", IPv4(iph->saddr));
	trace_printk( "daddr          : "IPv4_FMT"\n", IPv4(iph->daddr));

	switch(iph->protocol){
		case 1:  ps = "ICMP"; break;
		case 4:  ps = "IPv4"; break;
		case 6:  ps = "TCP"; break;
		case 17: ps = "UDP"; break;
	}

	trace_printk( "iphdr.protocol : %s\n", ps);
}

static void snull_dump_tcp(struct tcphdr* tcph, char *caption)
{
	char buf[64] = {0};

	trace_printk("---------> %s <--------- \n", caption);
	trace_printk( "\nPrinting TCP header info:\n");

	sprintf(buf, "Flags -- ");

	if(tcph->fin == 1) strcat(buf, "[FIN]");
	if(tcph->syn == 1) strcat(buf, "[SYN]");
	if(tcph->rst == 1) strcat(buf, "[RST]");
	if(tcph->psh == 1) strcat(buf, "[PSH]");
	if(tcph->ack == 1) strcat(buf, "[ACK]");
	if(tcph->urg == 1) strcat(buf, "[URG]");
	if(tcph->ece == 1) strcat(buf, "[ECE]");
	if(tcph->cwr == 1) strcat(buf, "[CWR]");
	strcat(buf, "\n");

	trace_printk( "tcphdr.source  : %u\n", tcph->source);
	trace_printk( "tcphdr.dest    : %u\n", tcph->dest);
	trace_printk( "tcphdr.seq     : %u\n", tcph->seq);
	trace_printk( "tcphdr.ack_seq : %u\n", tcph->ack_seq);
	trace_printk( "tcphdr.window  : %u\n", tcph->window);
	trace_printk( "TCP Pkt type   : %s\n", buf);
}

static void snull_hex_dump(char *data, int size, char *caption)
{
	int i; // index in data...
	int j; // index in line...
	char temp[8];
	char buffer[128];
	char *ascii;

	memset(buffer, 0, 128);

	trace_printk("---------> %s <--------- (%d bytes from %p)\n", caption, size, data);

	// Printing the ruler...
	trace_printk("        +0          +4          +8          +c            0   4   8   c   \n");

	// Hex portion of the line is 8 (the padding) + 3 * 16 = 52 chars long
	// We add another four bytes padding and place the ASCII version...
	ascii = buffer + 58;
	memset(buffer, ' ', 58 + 16);
	buffer[58 + 16] = '\n';
	buffer[58 + 17] = '\0';
	buffer[0] = '+';
	buffer[1] = '0';
	buffer[2] = '0';
	buffer[3] = '0';
	buffer[4] = '0';
	for (i = 0, j = 0; i < size; i++, j++)
	{
		if (j == 16)
		{
			trace_printk("%s", buffer);
			memset(buffer, ' ', 58 + 16);

			sprintf(temp, "+%04x", i);
			memcpy(buffer, temp, 5);

			j = 0;
		}

		sprintf(temp, "%02x", 0xff & data[i]);
		memcpy(buffer + 8 + (j * 3), temp, 2);
		if ((data[i] > 31) && (data[i] < 127))
			ascii[j] = data[i];
		else
			ascii[j] = '.';
	}

	if (j != 0)
		trace_printk("%s", buffer);
	trace_printk("==========================\n");

}

void snull_dump_skb(const struct sk_buff *skb, char* message)
{
	struct ethhdr * eth_header = NULL;      // ETH Header
	struct tcphdr *tcp_header  = NULL;      // TCP Header
	struct iphdr *ip_header    = NULL;      // IP Header

	eth_header = eth_hdr(skb);
	ip_header = ip_hdr(skb);
	tcp_header = tcp_hdr(skb);

	if(skb)
		snull_dump_skb_info(skb, message);
	if(eth_header)
		snull_dump_ethh(eth_header, message);
	if(ip_header)
		snull_dump_ip(ip_header, message);
	if(tcp_header)
		snull_dump_tcp(tcp_header, message);
	if(skb->data)
		snull_hex_dump(skb->data, skb->len, message);
}

EXPORT_SYMBOL(snull_dump_skb);

static int __init snull_skb_debug_init(void)
{
	trace_printk ("snull_skb_debug loaded !\n");
	return 0;
}

static void __exit snull_skb_debug_exit(void)
{
	trace_printk ("Unloading snull_skb_debug module.\n");
	return;
}

MODULE_AUTHOR("Abhijeet Bhatikar");
MODULE_LICENSE("Dual BSD/GPL");

module_init(snull_skb_debug_init);
module_exit(snull_skb_debug_exit);
