#pragma once

int kprobe_task_create(struct kprobe* p, struct pt_regs* regs);
int kprobe_task_exit(struct kprobe* p, struct pt_regs* regs);
int kprobe_file_open(struct kprobe* p, struct pt_regs* regs);
int kprobe_file_read(struct kprobe* p, struct pt_regs* regs);
int kprobe_file_write(struct kprobe* p, struct pt_regs* regs);

