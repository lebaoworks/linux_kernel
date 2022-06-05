#include <linux/limits.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <asm/ptrace.h>
#include <asm/current.h>

#include "watcher.h"

MODULE_AUTHOR("Le Thieu Bao");
MODULE_DESCRIPTION("Test Module");
MODULE_LICENSE("GPL");

static struct kprobe kp_task_create = {
    .symbol_name = "wake_up_new_task",
    .pre_handler = kprobe_task_create
};

static struct kprobe kp_task_exit = {
    .symbol_name = "do_exit",
    .pre_handler = kprobe_task_exit
};

static struct kprobe kp_file_open = {
    .symbol_name = "vfs_open",
    .pre_handler = kprobe_file_open
};

static struct kprobe kp_file_read = {
    .symbol_name = "vfs_read",
    .pre_handler = kprobe_file_read
};

static struct kprobe kp_file_write = {
    .symbol_name = "vfs_write",
    .pre_handler = kprobe_file_write
};

int kprobe_task_create(struct kprobe* p, struct pt_regs* regs)
{
    struct task_struct* task = (struct task_struct*) regs->di;
    struct mm_struct* mm = task->mm;
    if (task->pid)
    {
        char* arg_buffer = kzalloc(PAGE_SIZE+1, GFP_KERNEL);
        int len = min(mm->arg_end - mm->arg_start, PAGE_SIZE);
        access_process_vm(task, mm->arg_start, arg_buffer, len, 0);
        printk("[process_create] parent: %d\tchild: %d\tpath: %s\n", current->pid, task->pid, arg_buffer);
        kfree(arg_buffer);
    }
    // else
    //     printk("process %d create new thread", current->pid);
    return 0;
}

int kprobe_task_exit(struct kprobe* p, struct pt_regs* regs)
{
    printk("[process_exit] PID: %d\texit_code: %lu", current->pid, regs->di);
    return 0;
}

int kprobe_file_open(struct kprobe* p, struct pt_regs* regs)
{
    struct path* path = (struct path*) regs->di;   
    char* buffer = kzalloc(PATH_MAX, GFP_KERNEL);
    char* pPath = dentry_path_raw(path->dentry, buffer, PAGE_SIZE);
    printk("[file_open] PID: %d\nfile_name: %s\tfile_path: %s\n", current->pid, path->dentry->d_name.name, pPath);
    kfree(buffer);
    return 0;
}

int kprobe_file_write(struct kprobe* p, struct pt_regs* regs)
{
    struct path* path = &((struct file*) regs->di)->f_path;
    char* buffer = kzalloc(PATH_MAX, GFP_KERNEL);
    char* pPath = dentry_path_raw(path->dentry, buffer, PAGE_SIZE);
    printk("[file_write] PID: %d\tfile: %s\n", current->pid, pPath);
    kfree(buffer);
    return 0;
}

int kprobe_file_read(struct kprobe* p, struct pt_regs* regs)
{
    struct path* path = &((struct file*) regs->di)->f_path;
    char* buffer = kzalloc(PATH_MAX, GFP_KERNEL);
    char* pPath = dentry_path_raw(path->dentry, buffer, PAGE_SIZE);
    printk("[file_read] PID: %d\tfile: %s\n", current->pid, pPath);
    kfree(buffer);
    return 0;
}

int init_watcher(void)
{
    printk(KERN_INFO "[%s] module loaded\tPAGE_FILE: %ld\n", __this_module.name, PAGE_SIZE);   
    register_kprobe(&kp_task_create);
    printk(KERN_INFO "[wake_up_new_task] address: %lx\n", (unsigned long) kp_task_create.addr);
    register_kprobe(&kp_task_exit);
    printk(KERN_INFO "[do_exit] address: %lx\n", (unsigned long) kp_task_exit.addr);
    register_kprobe(&kp_file_open);
    printk(KERN_INFO "[vfs_open] address: %lx\n", (unsigned long) kp_file_open.addr);
    register_kprobe(&kp_file_read);
    printk(KERN_INFO "[vfs_read] address: %lx\n", (unsigned long) kp_file_read.addr);
    register_kprobe(&kp_file_write);
    printk(KERN_INFO "[vfs_write] address: %lx\n", (unsigned long) kp_file_write.addr);
    return 0;
}

void exit_watcher(void)
{
    printk(KERN_INFO "[%s] module unloaded\n", __this_module.name);
    unregister_kprobe(&kp_task_create);
    unregister_kprobe(&kp_task_exit);
    unregister_kprobe(&kp_file_open);
    unregister_kprobe(&kp_file_write);
    unregister_kprobe(&kp_file_read);
}

module_init(init_watcher);
module_exit(exit_watcher);

