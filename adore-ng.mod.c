#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x4061a14b, "module_layout" },
	{ 0x1efe283f, "__cap_full_set" },
	{ 0x6c2e3320, "strncmp" },
	{ 0x973873ab, "_spin_lock" },
	{ 0x15b49f18, "d_alloc" },
	{ 0x5f030c2c, "dput" },
	{ 0x176407fe, "iput" },
	{ 0x20901d32, "d_lookup" },
	{ 0xd0d8621b, "strlen" },
	{ 0x1e6d26a8, "strstr" },
	{ 0x34bccd67, "filp_close" },
	{ 0xb72397d5, "printk" },
	{ 0xbbde6ccf, "filp_open" },
	{ 0x8cd5eba7, "per_cpu__current_task" },
	{ 0x198a6e2, "init_task" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "29AAA1A92E11C78917F4DB3");
