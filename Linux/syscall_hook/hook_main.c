#include <linux/init.h>             
#include <linux/module.h>
#include <linux/kallsyms.h>         // kallsyms_lookup_name
#include <linux/kernel.h>           // copy_from_user


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arthurian");

unsigned long *g_sys_call_table = NULL;

long (*sys_open)(const struct pt_regs *);
long (*sys_openat)(const struct pt_regs *);

long my_open(const struct pt_regs *regs)
{
    printk(KERN_ALERT "open hook\n");
    return sys_open(regs);
}

long my_openat(const struct pt_regs *regs)
{
    char szFileName[256] = { 0 };
    copy_from_user(szFileName, (char *)regs->si, sizeof(szFileName) - 1);
    if ((regs->dx & O_CREAT) && strcmp(szFileName, "/dev/null") != 0) {
        printk(KERN_INFO "openat: rdi:%016lx rsi:%016lx rdx:%016lx r10:%016lx\n", regs->di, regs->si, regs->dx, regs->r10);
        printk(KERN_ALERT "create %s\n", szFileName);
    }

    return sys_openat(regs);
}

void disable_write_protection(void)
{
    asm("mov %%cr0,%%rax\n\t"
        "and $0xfffffffffffeffff,%%rax\n\t"
        "mov %%rax,%%cr0"
        :
        :
        :"%rax");
}

void enable_write_protection(void)
{
    asm("mov %%cr0,%%rax\n\t"
        "or  $0x10000,%%rax\n\t"
        "mov %%rax,%%cr0"
        :
        :
        :"%rax");
}


int syscall_hook_init(void)
{
    g_sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    printk(KERN_ALERT "syscall table address:%lx\n", (unsigned long)g_sys_call_table);
    printk(KERN_INFO "__NR_open: %d\n", __NR_open);
    return 0;
}

int syscall_hook(void)
{
    printk(KERN_INFO "%s %d\n", __func__, __LINE__);
    sys_open = (long (*)(const struct pt_regs *))g_sys_call_table[__NR_open];
    sys_openat = (long (*)(const struct pt_regs *))g_sys_call_table[__NR_openat];
    disable_write_protection();
    g_sys_call_table[__NR_open] = (unsigned long)my_open;
    g_sys_call_table[__NR_openat] = (unsigned long)my_openat;
    enable_write_protection();
    printk(KERN_INFO "%s %d\n", __func__, __LINE__);
    return 0;
}

int syscall_unhook(void)
{
    printk(KERN_INFO "%s %d\n", __func__, __LINE__);
    disable_write_protection();
    g_sys_call_table[__NR_open] = (unsigned long)sys_open;
    g_sys_call_table[__NR_openat] = (unsigned long)sys_openat;
    enable_write_protection();
    printk(KERN_INFO "%s %d\n", __func__, __LINE__);
    return 0;
}


int hook_init(void)
{
    printk(KERN_INFO "Module init\n");
    syscall_hook_init();

    syscall_hook();
    return 0;
}

void hook_exit(void)
{
    syscall_unhook();
    printk(KERN_INFO "Module exit\n");
}

module_init(hook_init);
module_exit(hook_exit);