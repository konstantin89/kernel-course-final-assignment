/**
* @file:   net_felt.c
* @author: Kosta Bulgakov
* @brief:  Final assignment for Linux kernel course in Allot
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
#include <linux/list.h>
#include <linux/moduleparam.h>
#include <linux/delay.h>
#include <linux/stat.h>
#include <linux/if.h>

/**
 * @var: cache_ttl_sec
 * @brief: Module parameter that is represeting the TTL (time to live) for each cache entry.
 */
static long cache_ttl_sec = 0;
module_param(cache_ttl_sec, long, 0755);

#define FORMAT_BUFFER_SIZE 256
#define PROC_WRITE_BUFFER_SIZE 32

static spinlock_t g_cache_lock;

#define PROC_FILE_NAME "netfilter_proc_file"
static struct proc_dir_entry *g_proc_fs_entry;

static struct list_head g_cache_head;

#define MAX_CACHE_SIZE 50
static long g_cache_size = 0;

#define MAC_ADDRESS_SIZE 6

#define TIMER_INTERVAL_MS 1000
static struct timer_list g_cache_timer;

struct FilterCacheEntry
{
    char mac_address[MAC_ADDRESS_SIZE];

    /**
     * @brief: String containing the network device of the ARP inbound request.
     *         IFNAMSIZ defined in linux/if.h. Its max device name in netdevice.h.
     */
    char network_device_name[IFNAMSIZ];
    
    long arrival_time_secs;
    
    struct list_head list;
};
  
/**
 * @function: proc_write
 * @brief: Write function of the proc file.
 */
static ssize_t proc_write(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos); 

/**
 * @function: proc_read
 * @brief: Read function of the proc file.
 */
static ssize_t proc_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos);

/**
 * @function: pop_oldest_cache_entry
 * @brief: Remove oldest entry from cache.
 */
static void pop_oldest_cache_entry(void);

/**
 * @function: pop_n_cache_entries
 * @brief: Remove N oldest entries from cache.
 * @param: cache_entries_to_remove - Number of entries to remove.
 */
static void pop_n_cache_entries(long cache_entries_to_remove);

/**
 * @function: trim_expired_cache_entries
 * @brief: Remove expired cache entries.
 *         Each cache entry has TTL(time to live) period defined by cache_ttl_sec.
 * @param: cache_ttl - Cache entry expiration time. If set to 0, all cache entries will be removed.
 */
static void trim_expired_cache_entries(long cache_ttl);

/**
 * @function: cache_timer_callback
 * @brief: Timer callback that is called each TIMER_INTERVAL_MS and removed all expired cache entries.
 */
static void cache_timer_callback( struct timer_list *t);

/**
 * @function: print_cache_entry_to_buffer
 * @brief: Function that used to print cache entry to buffer (in human readable format).
 * @param: entry - Cache entry to be printed.
 * @param: dest_buf - Destination buffer.
 * @param: dest_buf_size - Destination buffer size.
 * @returns: Number of bytes written to dest_buf. 
 */
static int print_cache_entry_to_buffer(struct FilterCacheEntry* entry, char* dest_buf, size_t dest_buf_size);

/**
 * @function: arp_in_hook
 * @brief: Netfilter hook function for ARP protocol.
 */
static unsigned int arp_in_hook (void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

static struct file_operations proc_file_ops = 
{
  .owner = THIS_MODULE,
  .read = proc_read,
  .write = proc_write,
};

static struct nf_hook_ops tr_hook_ops = 
{
    .hook = arp_in_hook,
    .pf = NFPROTO_ARP,
    .hooknum = NF_ARP_IN,
    .priority = INT_MIN,
};

static void trim_expired_cache_entries(long cache_ttl)
{
  long current_time = 0;
  long seconds_since_packet_arrived = 0;

  struct list_head *pos = NULL;
  struct list_head *temp = NULL;
  struct FilterCacheEntry *current_entry = NULL;

  current_time = ktime_get_seconds();

  list_for_each_safe(pos, temp, &g_cache_head) 
  {
    current_entry = list_entry(pos, struct FilterCacheEntry, list);

    seconds_since_packet_arrived = current_time - current_entry->arrival_time_secs;
    if(seconds_since_packet_arrived > cache_ttl)
    {
      // Cache entry has reached its TTL. Remove it.
      g_cache_size--;
      printk("Removing expired cache entry. New cache size [%ld].\n", g_cache_size);
      list_del(&current_entry->list);
      kfree(current_entry);
      current_entry  = NULL;
    }
  }
}

static void cache_timer_callback( struct timer_list *t)
{
  spin_lock(&g_cache_lock);
  printk("Timer callback is called \n");

  trim_expired_cache_entries(cache_ttl_sec);

  mod_timer( &g_cache_timer, jiffies + msecs_to_jiffies(TIMER_INTERVAL_MS));
  spin_unlock(&g_cache_lock);
}

static int print_cache_entry_to_buffer(struct FilterCacheEntry* entry, char* dest_buf, size_t dest_buf_size)
{
  int bytes_written = 0;

  if(NULL == entry)
  {
    printk("Error: Cache entry is NULL \n");
    return 0;
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
  long number_of_entries_to_remove = 0;
  char processed_input[PROC_WRITE_BUFFER_SIZE] = {0};
  int str_to_int_ret_code = 0;

  spin_lock(&g_cache_lock);
  printk("Proc file write handler. Data size: [%ld]\n", count);

  if(count > PROC_WRITE_BUFFER_SIZE)
  {
    printk("Error! Input too long. Length: [%ld], Max allowed: [%d]\n", count, PROC_WRITE_BUFFER_SIZE);
    goto exit;
  }

  if(copy_from_user(processed_input, ubuf, count))
  {
    printk("Error! Copy from user failed! \n");
    goto exit;
  }

  str_to_int_ret_code = kstrtol(processed_input, 10, &number_of_entries_to_remove);
  if(0 != str_to_int_ret_code)
  {
    printk("Error! kstrtol failed! \n");
    goto exit;
  }

  printk("Removing [%ld] cache entries\n", number_of_entries_to_remove);

  pop_n_cache_entries(number_of_entries_to_remove);

exit:
  spin_unlock(&g_cache_lock);
  return count;
}

static ssize_t proc_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
  ssize_t total_bytes_written = 0;
  int entry_bytes_written = 0;
  char format_buffer[FORMAT_BUFFER_SIZE];
  struct list_head *pos = NULL;
  struct FilterCacheEntry *current_entry = NULL;

  spin_lock(&g_cache_lock);

  printk("Proc file read handler. Bytes count: [%lu], Current cache size: [%ld]\n", count, g_cache_size);

  if(*ppos > 0)
  {
    // We done writing cache to the proc file. 
    // Returning zero will let the reader know that there is no more data to read.
    total_bytes_written = 0;
    goto exit;
  }

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

  *ppos += total_bytes_written;

exit:
  spin_unlock(&g_cache_lock);
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
    kfree(head);
    head  = NULL;

    g_cache_size--;

    printk("Cache entry removed. Current count [%ld] \n", g_cache_size);
}

static void pop_n_cache_entries(long cache_entries_to_remove)
{
  long index = 0;

  if(cache_entries_to_remove > g_cache_size)
  {
    printk("Requested removing [%ld] cache entries, while current cache size is [%ld] \n", 
            cache_entries_to_remove, g_cache_size);

    cache_entries_to_remove = g_cache_size;
  }

  printk("Removing [%ld] cache entries \n", cache_entries_to_remove);

  for(index=0; index<cache_entries_to_remove; index++)
  {
    pop_oldest_cache_entry();
  }
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
    entry->arrival_time_secs = ktime_get_seconds();
    
    if(g_cache_size >= MAX_CACHE_SIZE)
    {
      printk("Cache max size of [%d] entries reached \n", MAX_CACHE_SIZE);
      pop_oldest_cache_entry();
    }

    INIT_LIST_HEAD(&entry->list);
    list_add_tail(&entry->list, &g_cache_head);
    g_cache_size++;

    printk("Cache entry added. Current count [%ld] \n", g_cache_size);
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

    printk("Netfilter module is loading. Cache TTL is [%ld]\n", cache_ttl_sec);
    
    spin_lock_init(&g_cache_lock);
    INIT_LIST_HEAD(&g_cache_head);

    g_proc_fs_entry = proc_create(PROC_FILE_NAME, S_IALLUGO, NULL, &proc_file_ops);
    
    if(NULL == g_proc_fs_entry)
    {
      printk("Error, failed creating proc file. \n");
      return -1;
    }

    err = nf_register_net_hook (&init_net, &tr_hook_ops);

    timer_setup( &g_cache_timer, cache_timer_callback, 0);
    mod_timer( &g_cache_timer, jiffies + msecs_to_jiffies(TIMER_INTERVAL_MS));
    
    return err;
}

static void __exit net_exit (void)
{
    printk("Netfilter module is unloading.\n");

    while(0 != del_timer( &g_cache_timer ))
    {
      printk("Failed to delete timer. Timer is still in use! Sleep few ms and try again. \n");
      msleep(100);
    }

    nf_unregister_net_hook(&init_net, &tr_hook_ops);
    proc_remove(g_proc_fs_entry);

    // Remove all cache entries.
    // The param cache_ttl=0 will expire all cache entires and remove them.
    trim_expired_cache_entries(0);

    return;
}

module_init(net_init);
module_exit(net_exit);
MODULE_LICENSE("GPL");
MODULE_VERSION ("1.0");
