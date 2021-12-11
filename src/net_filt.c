/**
* @file:   net_felt.c
* @author: Kosta Bulgakov
* @breif:  Final assignment for Linux kernel course in Allot
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netfilter_arp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/version.h>

#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/proc_fs.h>

static spinlock_t g_cache_lock;

#define PROC_FILE_NAME "netfilter_proc_file"
static struct proc_dir_entry *g_proc_fs_entry;

static long g_cache_entry_ttl_ns = 0;
static struct list_head g_cache_head;

#define MAX_CACHE_SIZE 50
static int g_cache_size = 0;

#define MAC_ADDRESS_SIZE 8
#define DEVICE_NAME_MAX_SIZE 16

struct FilterCacheEntry
{
    char mac_address[MAC_ADDRESS_SIZE];
    unsigned int source_ipv4 ; 
    char network_device_name[DEVICE_NAME_MAX_SIZE];
    
    long arrival_time_ns;
    
    struct list_head list;
};
  
static ssize_t proc_write(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos); 
static ssize_t proc_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos);

static struct file_operations proc_file_ops = 
{
	.owner = THIS_MODULE,
	.read = proc_read,
	.write = proc_write,
};

static unsigned int arp_in_hook (void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

static struct nf_hook_ops tr_hook_ops = 
{
    .hook = arp_in_hook,
    .pf = NFPROTO_ARP,
    .hooknum = NF_ARP_IN,
    .priority = INT_MIN,
};





static ssize_t proc_write(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
	printk("Proc file write handler\n");
	return -1;
}

static ssize_t proc_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
	printk("Proc file read handler\n");
	return 0;
}

static void pop_oldest_cache_entry(void)
{
    struct FilterCacheEntry *head;

    if(list_empty(&g_cache_head))
    {
        return;
    }

    head = list_first_entry(&g_cache_head, struct FilterCacheEntry, list);
    list_del(&head->list);
    g_cache_size--;
}

static void add_data_to_cache(char *mac_head, struct iphdr *ip_header)
{
    struct FilterCacheEntry *entry = NULL;
  
    entry = kmalloc(sizeof(struct FilterCacheEntry), GFP_KERNEL);
    if(NULL == entry)
    {
      printk("Error: Failed to allocate cache entry \n");
      return;
    }

    memcpy(&mac_head[6],entry->mac_address, MAC_ADDRESS_SIZE);
    //entry->source_ipv4 = (unsigned int)ip_header->saddr;
    entry->source_ipv4 = 0;
    strcpy("temp", entry->network_device_name); ////////////////////// Todo - place dev name here
    entry->arrival_time_ns = ktime_get_ns();
    
    if(g_cache_size >= MAX_CACHE_SIZE)
    {
      pop_oldest_cache_entry();
    }

    INIT_LIST_HEAD(&entry->list);
    list_add_tail(&entry->list, &g_cache_head);
    g_cache_size++;
}

static unsigned int arp_in_hook (void *priv,
                                 struct sk_buff *skb,
                                 const struct nf_hook_state *state)
{

    spin_lock(&g_cache_lock);

    char *mac_head = NULL;
    struct iphdr *ip_header = NULL; //https://docs.huihoo.com/doxygen/linux/kernel/3.7/structiphdr.html
    
    if(NULL == skb)
    {
        goto exit;
    }

    ip_header = NULL; //(struct iphdr *)skb_network_header(skb);
    mac_head = skb_mac_header(skb);

    if((NULL == mac_head))
    {
      printk("Error: Mac header is NULL \n");
      goto exit;
    }

    if((NULL == ip_header))
    {
      printk("[X] Error: IPv4 header is NULL \n");
      goto exit;
    }

    //add_data_to_cache(mac_head, ip_header);

    //printk ("%02x:%02x:%02x:%02x:%02x:%02x\n",mac_head[6]&0xff,mac_head[7]&0xff,mac_head[8]&0xff,mac_head[9]&0xff,mac_head[10]&0xff,mac_head[11]&0xff);

exit:
    spin_unlock(&g_cache_lock);
    return NF_ACCEPT;
}


static int __init net_init(void)
{
    int err = 0;

    printk("Netfilter module is loading. Cache TTL is [%ld]\n", g_cache_entry_ttl_ns);
    
    spin_lock_init(&g_cache_lock);
    INIT_LIST_HEAD(&g_cache_head);
    g_proc_fs_entry = proc_create(PROC_FILE_NAME, 0660, NULL, &proc_file_ops);
    
    if(NULL == g_proc_fs_entry)
    {
      printk("Error, failed creating proc file. \n");
      return -1;
    }

    //err = nf_register_net_hook (&init_net, &tr_hook_ops);
    
    return err;
}

static void __exit net_exit (void)
{
    printk("Netfilter module is unloading.\n");

    nf_unregister_net_hook (&init_net, &tr_hook_ops);
    proc_remove(g_proc_fs_entry);

    return;
}

module_init(net_init);
module_exit(net_exit);
MODULE_LICENSE("GPL");
MODULE_VERSION ("1.0");
