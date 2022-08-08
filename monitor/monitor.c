#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kallsyms.h>

/**
 * Syscall monitor. Written with help from two resources:
 *      https://stackoverflow.com/a/65647294
 *      https://github.com/xcellerator/linux_kernel_hacking/issues/3
 *
 * Kernels newer than 5.7.0 require manual kallsyms_lookup_name() resolution.
 *
 * This module rewrites the system table to add more "logic"
 *    (in this case, a kernel print).
 *
 * Check out asm/ptrace.h for the pt_regs struct definition.
 * Useful for getting register values in the logging function.
*/

MODULE_LICENSE("GPL");

typedef int (* syscall_wrapper)(struct pt_regs *);

#define WATCHED_CALL __NR_getuid

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
typedef unsigned long (* kallsyms_lookup_name_t)(const char* name);

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

unsigned long sys_call_table_addr;

int enable_page_rw(void *ptr){
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long) ptr, &level);

    if(pte->pte & ~_PAGE_RW){
        pte->pte |= _PAGE_RW;
    }

    return 0;
}

int disable_page_rw(void *ptr){
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long) ptr, &level);
    pte->pte = pte->pte & ~_PAGE_RW;
    return 0;
}

syscall_wrapper original_syscall;

//asmlinkage int log_syscall(int sockfd, const struct sockaddr *addr, int addrlen) {
int log_syscall(struct pt_regs *regs) {
    pr_info("[monitor] getuid was called\n");
    return (*original_syscall)(regs);
}

static int __init logger_init(void) {
    pr_info("[monitor] module has been loaded\n");

    // Only run the kprobe search if defined
#ifdef KPROBE_LOOKUP
    pr_info("[monitor] setting up, looking for address of kallsyms_lookup_name...\n");

    // Register kprobe using kprobe structure defined above.
    int ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("[monitor] register_kprobe failed, returned %d\n", ret);
        return ret;
    }

    pr_info("[monitor] kprobe registered. kallsyms_lookup_name found at 0x%px\n",
kp.addr);

    // Manually define kallsyms_lookup_name() function to point to the recovered address
    kallsyms_lookup_name_t kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;

    // Get rid of the kprobe, we don't need it anymore
    unregister_kprobe(&kp);

    pr_info("[monitor] kprobe unregistered. now to the meat and potatoes...\n");
#endif

    // We have kallsyms_lookup_name(). Get the sys_call_table address
    sys_call_table_addr = kallsyms_lookup_name("sys_call_table");
    
    pr_info("[monitor] sys_call_table@%lx\n", sys_call_table_addr);
    // Enable read/write of the syscall table
    enable_page_rw((void *)sys_call_table_addr);

    // Original syscall address (will change later to a different instruction)
    original_syscall = ((syscall_wrapper *)sys_call_table_addr)[WATCHED_CALL];
    if (!original_syscall) {
        pr_err("[monitor] Failed to find original syscall address\n");
        return -1;
    }

    // log_syscall is a modded version of the original function.
    //     It pr_info()s and returns
    ((syscall_wrapper *)sys_call_table_addr)[WATCHED_CALL] = log_syscall;

    // Disable read/write of the syscall table, we don't need it anymore
    disable_page_rw((void *)sys_call_table_addr);
    
    pr_info("[monitor] original_syscall = %p\n", original_syscall);
    return 0;
}

static void __exit logger_exit(void) {
    pr_info("[monitor] time to restore syscall...\n");
    
    // Enable read/write of the syscall table, so we can restore the instruction
    enable_page_rw((void *)sys_call_table_addr);

    // Restore syscall to original code
    ((syscall_wrapper *)sys_call_table_addr)[WATCHED_CALL] = original_syscall;

    // Disable read/write of the syscall table, we're done here
    disable_page_rw((void *)sys_call_table_addr);

    pr_info("[monitor] syscall restored. module has been unloaded\n");
}

module_init(logger_init);
module_exit(logger_exit);

