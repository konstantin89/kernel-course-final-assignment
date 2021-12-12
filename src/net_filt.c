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
#include <linux/moduleparam.h>


static long cache_ttl_ns = 0;
module_param(cache_ttl_ns, long, 0755);

#define FORMAT_BUFFER_SIZE 256
#define PROC_WRITE_BUFFER_SIZE 32

static spinlock_t g_cache_lock;

#define PROC_FILE_NAME "netfilter_proc_file"
static struct proc_dir_entry *g_proc_fs_entry;

static struct list_head g_cache_head;

#define MAX_CACHE_SIZE 50
static int g_cache_size = 0;

#define MAC_ADDRESS_SIZE 6
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




static int print_cache_entry_to_buffer(struct FilterCacheEntry* entry, char* dest_buf, size_t dest_buf_size)
{
  int bytes_written = 0;

  if(NULL == entry)
  {
    printk("Error: Cache entry is NULL \n");
  }

  bytes_written = snprintf(dest_buf, dest_buf_size, "MAC: [%02x:%02x:%02x:%02x:%02x:%02x], DEV: [%s]\n",
           entry->mac_address[0]&0xff,
           entry->mac_address[1]&0xff,
           entry->mac_address[2]&0xff,
           entry->mac_address[3]&0xff,
           entry->mac_address[4]&0xff,
           entry->mac_address[5]&0xff,
           entry->network_device_name);

  return bytes_written;
}

static ssize_t proc_write(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
  int number_of_entries_to_remove = 0;
  char processed_input[PROC_WRITE_BUFFER_SIZE] = {0};
  int index = 0;

  spin_lock(&g_cache_lock);
	printk("Proc file write handler. Data size: [%ld]\n", count);
/*
  if(count > PROC_WRITE_BUFFER_SIZE)
  {
    printk("Error! Input too long. Length: [%ld], Max allowed: [%d]\n", count, PROC_WRITE_BUFFER_SIZE);
  }

  if(copy_from_user(processed_input, ubuf, count))
  {
    printk("Error! Copy from user failed! \n");
  }

  for(index=0; index<count; count++)
  {
    // Remove all non numeric characters from input.
    if((processed_input[index] < 48) ||(processed_input[index] > 57) )
    {
      processed_input[index] = '\0';
    }
  }
*/
  //kstrtoint(processed_input, 10, &number_of_entries_to_remove);
  printk("Removing [%d] cache entries\n", number_of_entries_to_remove);

exit:
  spin_unlock(&g_cache_lock);
	return count;
}

static ssize_t proc_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
  ssize_t total_bytes_written = 0;
  int entry_bytes_written = 0;
  char format_buffer[FORMAT_BUFFER_SIZE];

  spin_lock(&g_cache_lock);

	printk("Proc file read handler. Bytes count: [%lu], Current cache size: [%d]\n", count, g_cache_size);

  struct list_head *pos = NULL;
  struct FilterCacheEntry *current_entry = NULL;

  list_for_each(pos, &g_cache_head) 
  {
    current_entry = list_entry(pos, struct FilterCacheEntry, list);
    entry_bytes_written = print_cache_entry_to_buffer(current_entry, format_buffer, FORMAT_BUFFER_SIZE);

    if(copy_to_user(ubuf + total_bytes_written, format_buffer, entry_bytes_written))
    {
      return -EFAULT;
    }

    total_bytes_written += entry_bytes_written;
  }

  spin_unlock(&g_cache_lock);

  *ppos += total_bytes_written;
	return total_bytes_written;
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

    printk("Cache entry removed. Current count [%d] \n", g_cache_size);
}

static void add_data_to_cache(char *mac_head, char *net_device_name)
{
    struct FilterCacheEntry *entry = NULL;
  
    entry = kmalloc(sizeof(struct FilterCacheEntry), GFP_KERNEL);
    if(NULL == entry)
    {
      printk("Error: Failed to allocate cache entry \n");
      return;
    }

    memcpy(&mac_head[6],entry->mac_address, MAC_ADDRESS_SIZE);
    strcpy(entry->network_device_name, net_device_name); 
    entry->arrival_time_ns = ktime_get_ns();
    
    if(g_cache_size >= MAX_CACHE_SIZE)
    {
      printk("Cache max size of [%d] entries reached \n", MAX_CACHE_SIZE);
      pop_oldest_cache_entry();
    }

    INIT_LIST_HEAD(&entry->list);
    list_add_tail(&entry->list, &g_cache_head);
    g_cache_size++;

    printk("Cache entry added. Current count [%d] \n", g_cache_size);
}

static unsigned int arp_in_hook (void *priv,
                                 struct sk_buff *skb,
                                 const struct nf_hook_state *state)
{
    char *mac_head = NULL;
    char* net_device_name = NULL;
    
    spin_lock(&g_cache_lock);

    if(NULL == skb)
    {
        goto exit;
    }

    mac_head = skb_mac_header(skb);

    if((NULL == skb->dev) || (NULL == skb->dev->name))
    {
      printk("Error: Network device is NULL \n");
      goto exit;
    }

    net_device_name = skb->dev->name;

    if((NULL == mac_head))
    {
      printk("Error: Mac header is NULL \n");
      goto exit;
    }

     add_data_to_cache(mac_head, net_device_name);

exit:
    spin_unlock(&g_cache_lock);
    return NF_ACCEPT;
}


static int __init net_init(void)
{
    int err = 0;

    printk("Netfilter module is loading. Cache TTL is [%ld]\n", cache_ttl_ns);
    
    spin_lock_init(&g_cache_lock);
    INIT_LIST_HEAD(&g_cache_head);

    g_proc_fs_entry = proc_create(PROC_FILE_NAME, 0666, NULL, &proc_file_ops);
    
    if(NULL == g_proc_fs_entry)
    {
      printk("Error, failed creating proc file. \n");
      return -1;
    }

    err = nf_register_net_hook (&init_net, &tr_hook_ops);
    
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
