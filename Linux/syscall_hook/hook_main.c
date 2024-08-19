#include <linux/init.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arthurian");

int hook_init(void)
{
    printk(KERN_INFO "Begin\n");
    return 0;
}

void hook_exit(void)
{
    printk(KERN_INFO "End\n");
}

module_init(hook_init);
module_exit(hook_exit);