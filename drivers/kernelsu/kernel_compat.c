#include <linux/kernel.h>
#include <linux/fs.h>

bool ksu_vfs_read_hook __read_mostly = false;
bool ksu_execveat_hook __read_mostly = false;
bool ksu_input_hook __read_mostly = false;

int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void **arg) { return 1; }
int ksu_handle_faccessat(int *dfd, const void **filename_user, int *mode, int *flags) { return 0; }
int ksu_handle_sys_read(unsigned int fd, void **buf_ptr, size_t *count_ptr) { return 0; }
int ksu_handle_stat(int *dfd, const void **filename_user, int *flags) { return 0; }
void ksu_handle_newfstat_ret(void *fd, void *statbuf_ptr) {}
void ksu_handle_fstat64_ret(void *fd, void *statbuf_ptr) {}
int ksu_handle_execveat(int *fd, void **filename_ptr, void *argv, void *envp, int *flags) { return 0; }

u32 susfs_ksu_sid = 0;
u32 susfs_priv_app_sid = 0;
bool susfs_is_current_ksu_domain(void) { return false; }

int path_mount(const char *dev_name, struct path *path, const char *type_page, unsigned long flags, void *data_page) {
    return 0;
}

#include <linux/sched.h>
extern void put_seccomp_filter(struct task_struct *tsk);
void seccomp_filter_release(struct task_struct *tsk) {
#ifdef CONFIG_SECCOMP
    put_seccomp_filter(tsk);
#endif
}
