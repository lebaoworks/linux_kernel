#pragma once

#include <linux/module.h>
#include <linux/kprobes.h>

static unsigned long (*_kallsyms_lookup_name) (const char*) = NULL;
static unsigned long lookup_name(const char* name)
{
    if (!_kallsyms_lookup_name)
    {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)   
    pr_debug("kallsyms_lookup_name not exported, finding...");
    struct kprobe kp = {.symbol_name = "kallsyms_lookup_name"};
    register_kprobe(&kp);
    _kallsyms_lookup_name = (unsigned long (*) (const char*)) kp.addr;
    unregister_kprobe(&kp);
#else
    _kallsyms_lookup_name = kallsyms_lookup_name;
#endif
    pr_debug("kallsyms_lookup_name address: %p\n", _kallsyms_lookup_name);
    }
    return _kallsyms_lookup_name(name);
}
