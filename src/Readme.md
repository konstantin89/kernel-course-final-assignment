# Netfilter home assignment

## Delivered Files

`Readme.md` - This file.  
`net_filt.c` - Source file of the loadable kernel module.  
`Makefile` - Makefile of the loadable kernel module.  

Please note that the readme file is in Markdown format.   
Online MD file viewer like https://dillinger.io/  can be used.   
Just copy the content of the file there.  

## Usage commands
```
# Compile module
make 

# Install module
sudo make i

# Remove module
sudo make r
```

## Design notes

### Cache entry structure
Each cache entry is represented by the following structure:
```
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
```

Note that since the netfilter hook in on ARP protocol (MAC layer), the sk_buff has an empty IP header.     
From my observation this field indeed is always zero.  


### Cache TTL implementation
Cache TTL is managed by timer. Each second, the timer runs a routine that  
iterates over the cache, and removes all the expired entries.    

If cache is reached its maximum size and a new entry is inserted,  
the oldest entry will be removed to make space for the new one.  

### Synchronisation
Since the access to the cache can be done from multiple threads, synchronization is needed.  
`Spin lock` is used to sync all cache accesses.  


## Proc file

The file `/proc/netfilter_proc_file` is created by the net_filt module.  
This file can be used to interact with the ARP cache that is stored in the   
kernel space.  

### Reading from proc file
Reading from `/proc/netfilter_proc_file`, will print all the cache content in human readable format.  

Usage example:
```
$ sudo cat /proc/netfilter_proc_file
MAC: [4c:27:3e:c9:65:b5], DEV: [ens160]
MAC: [8c:22:3e:c9:65:b5], DEV: [ens160]
MAC: [8c:2c:3e:c9:65:b5], DEV: [ens160]
MAC: [0c:2b:3e:c9:65:b5], DEV: [ens160]
MAC: [4c:2d:3e:c9:65:b5], DEV: [ens160]
MAC: [8c:21:3e:c9:65:b5], DEV: [ens160]
MAC: [8c:2f:3e:c9:65:b5], DEV: [ens160]
MAC: [cc:21:3e:c9:65:b5], DEV: [ens160]
```

### Writing to proc file
Writing number N to the `/proc/netfilter_proc_file`, will cause the module   
deleting N cache entries. 

Non numerical inputs will be ignored.  
If N is larger that the current cache size, all cache entries will be removed.  

Usage example:
```
sudo echo 6  > /proc/netfilter_proc_file
```
