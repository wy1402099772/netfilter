/* Light-weight Fire Wall. Simple firewall utility based on 
* Netfilter for 2.4. Designed for educational purposes. 
*  
* Written by bioforge  -  March 2003. 
*/  
  
  
#include <linux/kernel.h>  
#include <linux/init.h>  
#include <linux/module.h>  
#include <linux/version.h>  
#include <linux/string.h>  
#include <linux/kmod.h>  
#include <linux/vmalloc.h>  
#include <linux/workqueue.h>  
#include <linux/spinlock.h>  
#include <linux/socket.h>  
#include <linux/net.h>  
#include <linux/in.h>  
#include <linux/skbuff.h>  
#include <linux/ip.h>  
#include <linux/tcp.h>  
#include <linux/udp.h>
#include <linux/netfilter.h>  
#include <linux/netfilter_ipv4.h>  
#include <linux/icmp.h>  
#include <net/sock.h>  
#include <asm/uaccess.h>  
#include <asm/unistd.h>  
#include <linux/if_arp.h>  
#include <linux/cdev.h>           // struct cdev  
#include <linux/timekeeping.h>
  
#include "lwfw.h"  

MODULE_LICENSE("GPL");  
MODULE_AUTHOR("xsc"); 
  
/* Local function prototypes */    
static int copy_stats(struct lwfw_stats *statbuff);  
  
/* Some function prototypes to be used by lwfw_fops below. */  
//static int lwfw_ioctl( struct file *file, unsigned int cmd, unsigned long arg);
static long lwfw_ioctl( struct file *file, unsigned int cmd, unsigned long arg);  
static int lwfw_open(struct inode *inode, struct file *file);  
static int lwfw_release(struct inode *inode, struct file *file);  
  
  
/* Various flags used by the module */  
/* This flag makes sure that only one instance of the lwfw device 
* can be in use at any one time. */  
static int lwfw_ctrl_in_use = 0;  
  
/* This flag marks whether LWFW should actually attempt rule checking. 
* If this is zero then LWFW automatically allows all packets. */  
static int active = 0;  
  
/* Specifies options for the LWFW module */
/*  
static unsigned int lwfw_options = (LWFW_IF_DENY_ACTIVE 
				| LWFW_IP_DENY_ACTIVE 
				| LWFW_PORT_DENY_ACTIVE);  
*/

static int major = 0;  /* Control device major number */  
  
/* This struct will describe our hook procedure. */  
static struct nf_hook_ops nfho0;
static struct nf_hook_ops nfho1;
static struct nf_hook_ops nfho2;
static struct nf_hook_ops nfho3;
static struct nf_hook_ops nfho4;  
  
/* Module statistics structure */  
static struct lwfw_stats lwfw_statistics = {0, 0, 0, 0, 0};  
  
/* Actual rule 'definitions'. */  
/* TODO:  One day LWFW might actually support many simultaneous rules. 
* Just as soon as I figure out the list_head mechanism... */  
static char *deny_if = NULL;                 /* Interface to deny */  
static unsigned int deny_ip = 0x00000000;    /* IP address to deny */  
static unsigned short deny_port = 0x0000;   /* TCP port to deny */  

struct cdev cdev_m;  
  
unsigned int inet_addr(char *str)     
{     
    int a,b,c,d;     
    char arr[4];     
    sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d);     
    arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;     
    return *(unsigned int*)arr;     
}     

#define RULEAMOUNT (200)
struct rule ruleArray[RULEAMOUNT];
static int indicator = 0;

  
/*  
* This is the interface device's file_operations structure 
*/  
struct file_operations  lwfw_fops = {  
	.owner = THIS_MODULE,   
    
     	.unlocked_ioctl = lwfw_ioctl,  
  
    	.open = lwfw_open,  
  
	.release = lwfw_release,      
};  

void clearRuleArray(void)
{
	int i = 0;
	for( ; i < indicator; i++)
	{
		ruleArray[i].enable = 0;
	}
	indicator = 0;
}

int atoi(char *str)
{
	int l = 0;
	int i = 0;
	for(; str[i] != 0; i++)
	{
		l = l * 10 + str[i] - '0';
	}
	return l;
}

void addNewRule(char *str)
{
	char tmpStore[7][20];
	int i = 0, j = 1;
	int k = 0;
	for(; i < 7 && str[j] != '\0'; j++)
	{
		if(str[j] == '@')
		{
			tmpStore[i][k] = '\0';
			i++;
			k = 0;
			continue;
		}
		tmpStore[i][k++] = str[j];
	}

	if(tmpStore[0][0] != '\0')
	{
		strcpy(ruleArray[indicator].srcIP, tmpStore[0]);
	}
	else
		ruleArray[indicator].srcIP[0] = '\0';
	if(tmpStore[1][0] != '\0')
	{
		ruleArray[indicator].srcPort = atoi(tmpStore[1]);
	}
	else
		ruleArray[indicator].srcPort = -1;
	if(tmpStore[2][0] != '\0')
	{
		strcpy(ruleArray[indicator].destIP, tmpStore[2]);
	}
	else
		ruleArray[indicator].destIP[0] = '\0';
	if(tmpStore[3][0] != '\0')
	{
		ruleArray[indicator].destPort = atoi(tmpStore[3]);
	}
	else
		ruleArray[indicator].destPort = -1;
	if(tmpStore[4][0] != '\0')
	{
		strcpy(ruleArray[indicator].protocol, tmpStore[4]);
	}
	if(tmpStore[5][0] != '\0')
	{
		ruleArray[indicator].time = atoi(tmpStore[5]);
	}
	else
		ruleArray[indicator].time = -1;
	if(tmpStore[6][0] != '\0')
	{
		strcpy(ruleArray[indicator].action, tmpStore[6]);
	}
	else
		strcpy(ruleArray[indicator].action, "ACCEPT");
	
	ruleArray[indicator].enable = 1;
	indicator++;

	return ;
}

void printRule(int i)
{
	printk("rule %d:%s, %d, %s, %d, %s, %d, %s\n", i, ruleArray[i].srcIP, ruleArray[i].srcPort, ruleArray[i].destIP, ruleArray[i].destPort, ruleArray[i].protocol, ruleArray[i].time,ruleArray[i].action);
}
	  
/* 
* This is the function that will be called by the hook 
*/  
unsigned int lwfw_hookfn(const struct nf_hook_ops *ops,
                   struct sk_buff *skb,
                   const struct nf_hook_state *state)
{ 
	if(state->hook 	!= 1 && state->hook != 3)
		return NF_ACCEPT;
	printk("Start hook Status: %u\n", state->hook);
	// if(!skb)
	// {
	// 	printk("skb == NULL\n");
	// }
	// else
	// {
	// 	printk("skb != NULL\n");
	// }
	struct sk_buff *sk = skb;//= skb_copy(skb, 1);  
    struct iphdr *ip;  
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    const struct iphdr *iph = NULL;
    __be16 dport;

    int destPort = -1;
    int srcPort = -1;
    char protocol[10];
    protocol[0] = '\0';

    if(!sk)  
	{
		printk("sk == NULL, accept\n");
		return NF_ACCEPT;
	} 


	ip = ip_hdr(sk);  
    iph = ip_hdr(skb);

    if(ip->protocol == IPPROTO_TCP)
    {
    	strcpy(protocol, "TCP");
        //printk("Protocol: TCP\n");
        tcph = (struct tcphdr *)(skb->data + (ip_hdr(skb)->ihl * 4));
        dport = tcph->dest;
        //printk("destination port:%d\n", ntohs(dport));
        destPort = ntohs(dport);

        dport = tcph->source;
        //printk("source port:%d\n", ntohs(dport));
    	srcPort = ntohs(dport);

    }
    else if(ip->protocol == IPPROTO_UDP)
    {
    	strcpy(protocol, "UDP");
        printk("Protocol: UDP\n");
        udph = (struct udphdr *)(skb->data + (ip_hdr(skb)->ihl * 4));
        dport = udph->dest;
        //printk("destination port:%d\n", ntohs(dport));
        destPort = ntohs(dport);

        dport = udph->source;
        //printk("source port: %d\n", dport);
        srcPort = ntohs(dport);
    }
    else if(ip->protocol == IPPROTO_ICMP)
    {
    	strcpy(protocol, "ICMP");
    	printk("Protocol: ICMP\n");
    }
    else
        printk("Other Protocol \n");
	  
    struct timeval currentTime;
    do_gettimeofday(&currentTime);		
    long int second = currentTime.tv_sec;
    int currentMinute = second/60 % 60;

    // printk("sourceIP:         ");
    // printk("%pI4\n", &(ip->saddr));
    // printk("destinationIP:    ");
    // printk("%pI4\n", &(ip->daddr)); 

	//return NF_ACCEPT;
	printk("indicator: %d\n", indicator);
    int i = 0;
    int confirmedRuleCount = 0;
    int needConfirmRuleCount = 0;
    for( ; i < indicator; i++)
    {
    	confirmedRuleCount = 0;
    	needConfirmRuleCount = 0;
    	printk("	sourceIP: %pI4 (%s)\n", &(ip->saddr), ruleArray[i].srcIP);
    	if(ruleArray[i].srcIP[0] != '\0')
    	{
    		needConfirmRuleCount++;
    		if(ip->saddr == inet_addr(ruleArray[i].srcIP))
    			confirmedRuleCount++;
    	}
    	
    	if(ruleArray[i].srcPort != -1)
    	{
    		needConfirmRuleCount++;
    		if(srcPort == ruleArray[i].srcPort)
    			confirmedRuleCount++;
    	}
    	
    	if(ruleArray[i].destIP[0] != '\0')
    	{
    		needConfirmRuleCount++;
    		if(ip->daddr == inet_addr(ruleArray[i].destIP))
    			confirmedRuleCount++;
    	}
    	
    	if(ruleArray[i].destPort != -1)
    	{
    		needConfirmRuleCount++;
    		if(destPort == ruleArray[i].destPort)
    			confirmedRuleCount++;
    	}
    	
    	if(ruleArray[i].protocol[0] != '\0')
    	{
    		needConfirmRuleCount++;
    		if(strcmp(protocol, ruleArray[i].protocol) == 0)
    			confirmedRuleCount++;
    	}
    	
    	if(ruleArray[i].time != -1)
    	{
    		needConfirmRuleCount++;
    		if(currentMinute == ruleArray[i].time)
    			confirmedRuleCount++;
    	}
    	
    	if(confirmedRuleCount > 0 && confirmedRuleCount == needConfirmRuleCount)
    	{
    		if(strcmp(ruleArray[i].action, "ACCEPT") == 0)
    			printk("firewall:ACCEPT");
    		else
    			printk("firewall:DROP");
    		printk("	sourceIP: %pI4 (%d)\n", &(ip->saddr), srcPort);
			printk("firewall:		destinationIP: %pI4 (%d)\n", &(ip->daddr), destPort);
			printk("firewall:protocol: %s, hook state:%d\n", protocol, state->hook);
			printk("firewall:because of the %d rule\n", i);
			printk("firewall:");
			printRule(i);
			printk("\n");

			if(strcmp(ruleArray[i].action, "ACCEPT") == 0)
    			return NF_ACCEPT;
    		else
    			return NF_DROP;

    	}

    }

 //    printk("Accept :	sourceIP: %pI4 (%d)\n", &(ip->saddr), srcPort);
	// printk("		destinationIP: %pI4 (%d)\n", &(ip->daddr), destPort);
	// printk("protocol: %s\n", protocol);
	// printk("do not confirm to all the %d rule\n", i);
	printk("ACCEPT\n");
	return NF_ACCEPT;               /* We are happy to keep the packet */  
}  

void clearStatInfo(void)
{
	lwfw_statistics.total_seen = 0;
	lwfw_statistics.tcp_dropped = 0;
	lwfw_statistics.total_dropped = 0;
	lwfw_statistics.ip_dropped = 0;
}
	  
/* Function to copy the LWFW statistics to a userspace buffer */  
static int copy_stats(struct lwfw_stats *statbuff)  
{  
	NULL_CHECK(statbuff);  
	  
	copy_to_user(statbuff, &lwfw_statistics,sizeof(struct lwfw_stats));  
	     
	return 0;  
}  
	   
	  
/*********************************************/  
/*  
* File operations functions for control device 
*/  
static long lwfw_ioctl( struct file *file, unsigned int cmd, unsigned long arg)  
{  
	int ret = 0;   
	switch (cmd) {  
		case LWFW_GET_VERS:  
	      		return LWFW_VERS;  
	    	case LWFW_ACTIVATE: {  
	       		active = 1;  
	       		printk("LWFW: Activated.\n");  
	       		if (!deny_if && !deny_ip && !deny_port) {  
	           		printk("LWFW: No deny options set.\n");  
	       		}  
	       		break;  
	    	}  
	    	case LWFW_DEACTIVATE: {  
	       		//active ^= active;  
	       		clearRuleArray();
	           	//printk("LWFW: Deactivated.\n");  
	       		break;  
	    	}  
	   	    case LWFW_GET_STATS: {  
	       		ret = copy_stats((struct lwfw_stats *)arg);  
	       		break;  
	    	}  
	    	case LWFW_REFRESH: {  
	    		//printk("name(arg) is %lu\n",arg);  
	        	printk("arguement:%s\n", arg);
	        	addNewRule(arg);
	        	printRule(indicator - 1);
	       		break;  
	    	}   
	    	default:  
	      		ret = -EBADRQC;  
	};   
	return ret;  
}  
	  
/* Called whenever open() is called on the device file */  
static int lwfw_open(struct inode *inode, struct file *file)  
{  
	if (lwfw_ctrl_in_use) {  
		return -EBUSY;  
	} 
	else {  
	      	lwfw_ctrl_in_use++;  
	      	return 0;  
	} 
 
	return 0;  
}  
	  
/* Called whenever close() is called on the device file */  
static int lwfw_release(struct inode *inode, struct file *file)  
{  
	lwfw_ctrl_in_use ^= lwfw_ctrl_in_use;  
	return 0;  
}  
	  
/*********************************************/  
/*
* Module initialisation and cleanup follow... 
*/  
static int init_lwfw(void)  
{  
	int result,err;  
	dev_t devno,devno_m;  
	  
	/* Register the control device, /dev/lwfw */  
	result = alloc_chrdev_region(&devno, 0, 1, LWFW_NAME);    
	major = MAJOR(devno);    
	  
	if (result < 0)    
		return result;    
	     
	devno_m = MKDEV(major, 0);    
	printk("major is %d\n",MAJOR(devno_m));   
	printk("minor is %d\n",MINOR(devno_m));  
	cdev_init(&cdev_m, &lwfw_fops);    
	cdev_m.owner = THIS_MODULE;  
	cdev_m.ops = &lwfw_fops;  
	err = cdev_add(&cdev_m, devno_m, 1);    
	if(err != 0 ){  
		printk("cdev_add error\n");  
	}  
	     
	/* Make sure the usage marker for the control device is cleared */  
	lwfw_ctrl_in_use ^= lwfw_ctrl_in_use;  
	  
	printk("\nLWFW: Control device successfully registered.\n");  
	     
	/* Now register the network hooks */  
	nfho0.hook = (nf_hookfn *)lwfw_hookfn;
    nfho0.owner = NULL;
    nfho0.pf = PF_INET;
    nfho0.hooknum = NF_INET_PRE_ROUTING;
    nfho0.priority=NF_IP_PRI_FIRST;

    nfho1.hook = (nf_hookfn *)lwfw_hookfn;
    nfho1.owner = NULL;
    nfho1.pf = PF_INET;
    nfho1.hooknum = NF_INET_LOCAL_IN;
    nfho1.priority=NF_IP_PRI_FIRST;

    nfho2.hook = (nf_hookfn *)lwfw_hookfn;
    nfho2.owner = NULL;
    nfho2.pf = PF_INET;
    nfho2.hooknum = NF_INET_FORWARD;
    nfho2.priority=NF_IP_PRI_FIRST;

    nfho3.hook = (nf_hookfn *)lwfw_hookfn;
    nfho3.owner = NULL;
    nfho3.pf = PF_INET;
    nfho3.hooknum = NF_INET_LOCAL_OUT;
    nfho3.priority=NF_IP_PRI_FIRST;

    nfho4.hook = (nf_hookfn *)lwfw_hookfn;
    nfho4.owner = NULL;
    nfho4.pf = PF_INET;
    nfho4.hooknum = NF_INET_POST_ROUTING;
    nfho4.priority=NF_IP_PRI_FIRST;     
	/* And register... */  
	nf_register_hook(&nfho0);// 注册一个钩子函数
    nf_register_hook(&nfho1);
    nf_register_hook(&nfho2);
    nf_register_hook(&nfho3);
    nf_register_hook(&nfho4);  
	     
	printk("LWFW: Network hooks successfully installed.\n");  
	     
	printk("LWFW: Module installation successful.\n");  
	return 0;  
}  
	  
static void cleanup_lwfw(void)  
{  
	//int ret;  
	     
	/* Remove IPV4 hook */  
   	nf_unregister_hook(&nfho0);
    nf_unregister_hook(&nfho1);
    nf_unregister_hook(&nfho2);
    nf_unregister_hook(&nfho3);
    nf_unregister_hook(&nfho4); 
  
   	/* Now unregister control device */  
   	cdev_del(&cdev_m);   
   	unregister_chrdev_region(MKDEV(major, 0), 1);  
  
   	/* If anything was allocated for the deny rules, free it here */  
   	if (deny_if)  
     		kfree(deny_if);  
     
   	printk("LWFW: Removal of module successful.\n");  
}  
  
module_init(init_lwfw);  
module_exit(cleanup_lwfw);  
 

