# Maps特征检测对抗


### 一、前言
maps文件在Android中一般指/proc/pid/maps，记录着每个进程的内存映射信息，也就是每个进程都会有一个对应的文件。在之前的特征分析中，发现像dobby hook框架、frida等工具都会造成maps中的数据改变，因此想深入分析下这种特征的形成原因以及可以采用什么方式进行对抗

### 二、maps文件形成
以微信进程为例，看看它的maps文件
```shell
selene:/ # cat /proc/9336/maps|head -n 10
020f4000-020f6000 r--p 00000000 fd:01 424                                /system/bin/app_process32
020f6000-020fa000 r-xp 00001000 fd:01 424                                /system/bin/app_process32
020fa000-020fb000 r--p 00004000 fd:01 424                                /system/bin/app_process32
020fb000-020fc000 rw-p 00004000 fd:01 424                                /system/bin/app_process32
020fc000-020fd000 rw-p 00000000 00:00 0                                  [anon:.bss]
12c00000-4af00000 rw-p 00000000 00:00 0                                  [anon:dalvik-main space (region space)]
57400000-57401000 ---p 00000000 00:00 0                                  [anon:partition_alloc]
57401000-57402000 rw-p 00000000 00:00 0                                  [anon:partition_alloc]
57402000-57404000 ---p 00000000 00:00 0                                  [anon:partition_alloc]
57404000-57430000 rw-p 00000000 00:00 0                                  [anon:partition_alloc]
```
从文件内容可以看到，每行内容都对应着一个地址段，可以划分为七列，在内核中每行数据使用vm_area_struct结构体，也就是VMA来表示
```c
// include/linux/mm_types.h

/*
 * This struct defines a memory VMM memory area. There is one of these
 * per VM-area/task.  A VM area is any part of the process virtual memory
 * space that has a special rule for the page-fault handlers (ie a shared
 * library, the executable area etc).
 */
struct vm_area_struct {
	/* The first cache line has the info for VMA tree walking. */

	unsigned long vm_start;		/* Our start address within vm_mm. */
	unsigned long vm_end;		/* The first byte after our end address
					   within vm_mm. */

	/* linked list of VM areas per task, sorted by address */
	struct vm_area_struct *vm_next, *vm_prev;

	struct rb_node vm_rb;

	/*
	 * Largest free memory gap in bytes to the left of this VMA.
	 * Either between this VMA and vma->vm_prev, or between one of the
	 * VMAs below us in the VMA rbtree and its ->vm_prev. This helps
	 * get_unmapped_area find a free area of the right size.
	 */
	unsigned long rb_subtree_gap;

	/* Second cache line starts here. */

	struct mm_struct *vm_mm;	/* The address space we belong to. */
	pgprot_t vm_page_prot;		/* Access permissions of this VMA. */
	unsigned long vm_flags;		/* Flags, see mm.h. */

	/*
	 * For areas with an address space and backing store,
	 * linkage into the address_space->i_mmap interval tree.
	 *
	 * For private anonymous mappings, a pointer to a null terminated string
	 * in the user process containing the name given to the vma, or NULL
	 * if unnamed.
	 */
	union {
		struct {
			struct rb_node rb;
			unsigned long rb_subtree_last;
		} shared;
		const char __user *anon_name;
	};

	/*
	 * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
	 * list, after a COW of one of the file pages.	A MAP_SHARED vma
	 * can only be in the i_mmap tree.  An anonymous MAP_PRIVATE, stack
	 * or brk vma (with NULL file) can only be in an anon_vma list.
	 */
	struct list_head anon_vma_chain; /* Serialized by mmap_sem &
					  * page_table_lock */
	struct anon_vma *anon_vma;	/* Serialized by page_table_lock */

	/* Function pointers to deal with this struct. */
	const struct vm_operations_struct *vm_ops;

	/* Information about our backing store: */
	unsigned long vm_pgoff;		/* Offset (within vm_file) in PAGE_SIZE
					   units */
	struct file * vm_file;		/* File we map to (can be NULL). */
	void * vm_private_data;		/* was vm_pte (shared mem) */

	atomic_long_t swap_readahead_info;
#ifndef CONFIG_MMU
	struct vm_region *vm_region;	/* NOMMU mapping region */
#endif
#ifdef CONFIG_NUMA
	struct mempolicy *vm_policy;	/* NUMA policy for the VMA */
#endif
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
#ifdef CONFIG_SPECULATIVE_PAGE_FAULT
	seqcount_t vm_sequence;
	atomic_t vm_ref_count;		/* see vma_get(), vma_put() */
#endif
} __randomize_layout;
```
而最终展示到maps文件中的是以下七列
|  列数   | 对应的vm_area_struct属性  |含义|
|  ----  | ----  |----  |
| “-”前一列，如00377000  | vm_start |此段虚拟地址空间起始地址  |
| “-”后一列，如00390000  | vm_end |此段虚拟地址空间结束地址  |
| 第三列，如r-xp  | vm_flags |此段虚拟地址空间的属性。每种属性用一个字段表示，r表示可读，w表示可写，x表示可执行，p和s共用一个字段，互斥关系，p表示私有段，s表示共享段，如果没有相应权限，则用’-’代替 |
| 第四列，如00000000  | vm_pgoff |对有名映射，表示此段虚拟内存起始地址在文件中以页为单位的偏移。对匿名映射，它等于0或者vm_start/PAGE_SIZE  |
| 第五列，如fd:00 | vm_file->f_dentry->d_inode->i_sb->s_dev |映射文件所属设备号。对匿名映射来说，因为没有文件在磁盘上，所以没有设备号，始终为00:00。对有名映射来说，是映射的文件所在设备的设备号  |
| 第六列，如9176473  | vm_file->f_dentry->d_inode->i_ino |映射文件所属节点号。对匿名映射来说，因为没有文件在磁盘上，所以没有节点号，始终为00:00。对有名映射来说，是映射的文件的节点号 |
| 第七列，如/lib/ld-2.5.so  |  |对有名来说，是映射的文件名。对匿名映射来说，是此段虚拟内存在进程中的角色。[stack]表示在进程中作为栈使用，[heap]表示堆。其余情况则无显示 |
含义中反复提到的两个词就是文件映射与匿名映射，文件是可以通过mmap来映射到一段内存区域上的，通常是给mmap传文件的fd，而最终会保存在vm_area_struct->vm_file属性中，因此这段内存区域就可以叫做普通文件映射区域，相反，匿名映射可以认为是进程主动申请一个空间使用，而这个空间没有关联任何一个文件

从maps的文件可以看出，文件映射主要指的是ELF文件，而通常单个ELF文件的对应的数据段都有三个或者四个
```shell
ea1b1000-ea1ca000 r--p 00000000 07:38 13                                 /apex/com.android.runtime/bin/linker
ea1ca000-ea251000 r-xp 00018000 07:38 13                                 /apex/com.android.runtime/bin/linker
ea251000-ea255000 r--p 0009e000 07:38 13                                 /apex/com.android.runtime/bin/linker
ea255000-ea256000 rw-p 000a1000 07:38 13                                 /apex/com.android.runtime/bin/linker
```
可以从权限中来区分ELF的不同数据段
- r-xp：代码段（.tetx），代码段对于进程来说只是只读可执行的，编译完成后不可随机修改
- rw-p：数据段（.data/.bss），数据段对于进程来说是可读可写但是只是数据，没有执行的权限
- r--p：只读数据段（.rodata），通常指一些全局静态常量等等

解析下vm_mm这个属性，vm_mm是指向跟该VMA相关的mm_struct结构体，而mm_struct结构体是表示整个maps文件的结构体
```c
struct mm_struct {
	struct vm_area_struct *mmap;		/* list of VMAs */
	struct rb_root mm_rb;
#ifdef CONFIG_SPECULATIVE_PAGE_FAULT
	rwlock_t mm_rb_lock;
#endif
	u64 vmacache_seqnum;                   /* per-thread vmacache */
#ifdef CONFIG_MMU
	unsigned long (*get_unmapped_area) (struct file *filp,
				unsigned long addr, unsigned long len,
				unsigned long pgoff, unsigned long flags);
#endif
    ......
#endif
} __randomize_layout;
```
关键的mmap属性是保存VMA的链表，整体流程大致是这样的
![](https://github.com/tcc0lin/self_pic/blob/main/map%E8%AF%BB%E5%8F%96%E6%B5%81%E7%A8%8B%E5%9B%BE.jpg?raw=true)
```c
static void
// 入参为文件指针以及vma指针
show_map_vma(struct seq_file *m, struct vm_area_struct *vma)
{
	struct mm_struct *mm = vma->vm_mm;
	struct file *file = vma->vm_file;
	vm_flags_t flags = vma->vm_flags;
	unsigned long ino = 0;
	unsigned long long pgoff = 0;
	unsigned long start, end;
	dev_t dev = 0;
	const char *name = NULL;

	if (file) {
        // 判断是否是普通文件映射，是的话则关联的几个字段都需要赋值
		struct inode *inode = file_inode(vma->vm_file);
		dev = inode->i_sb->s_dev;
		ino = inode->i_ino;
		pgoff = ((loff_t)vma->vm_pgoff) << PAGE_SHIFT;
	}

	start = vma->vm_start;
	end = vma->vm_end;
    // 打印前五列
	show_vma_header_prefix(m, start, end, flags, pgoff, dev, ino);

	/*
	 * Print the dentry name for named mappings, and a
	 * special [heap] marker for the heap:
	 */
	if (file) {
		seq_pad(m, ' ');
		seq_file_path(m, file, "\n");
		goto done;
	}

	if (vma->vm_ops && vma->vm_ops->name) {
		name = vma->vm_ops->name(vma);
		if (name)
			goto done;
	}

	name = arch_vma_name(vma);
    // 判断具体类型：文件、堆栈还是其他
	if (!name) {
		if (!mm) {
			name = "[vdso]";
			goto done;
		}

		if (vma->vm_start <= mm->brk &&
		    vma->vm_end >= mm->start_brk) {
			name = "[heap]";
			goto done;
		}

		if (is_stack(vma)) {
			name = "[stack]";
			goto done;
		}

		if (vma_get_anon_name(vma)) {
			seq_pad(m, ' ');
			seq_print_vma_name(m, vma);
		}
	}

done:
	if (name) {
		seq_pad(m, ' ');
		seq_puts(m, name);
	}
	seq_putc(m, '\n');
}

static void show_vma_header_prefix(struct seq_file *m,
				   unsigned long start, unsigned long end,
				   vm_flags_t flags, unsigned long long pgoff,
				   dev_t dev, unsigned long ino)
{
	seq_setwidth(m, 25 + sizeof(void *) * 6 - 1);
	seq_printf(m, "%08lx-%08lx %c%c%c%c %08llx %02x:%02x %lu ",
		   start,
		   end,
		   flags & VM_READ ? 'r' : '-',
		   flags & VM_WRITE ? 'w' : '-',
		   flags & VM_EXEC ? 'x' : '-',
		   flags & VM_MAYSHARE ? 's' : 'p',
		   pgoff,
		   MAJOR(dev), MINOR(dev), ino);
}
```
### 三、maps特征
上面大概了解了maps的形成以及展示过程后，结合hook框架中常暴露的特征来说下
#### 1 lsposed maps特征
目前手头上的项目是基于lsposed 1.6.0魔改的，因此以1.6.0的代码为例
```c
// core/src/main/cpp/main/src/context.cpp

void
Context::OnNativeForkSystemServerPost(JNIEnv *env, jint res) {
	if (res != 0) return;
	if (!skip_) {
		LoadDex(env);
		Service::instance()->HookBridge(*this, env);
		auto binder = Service::instance()->RequestBinderForSystemServer(env);
		if (binder) {
			InstallInlineHooks();
			Init(env);
			FindAndCall(env, "forkSystemServerPost", "(Landroid/os/IBinder;)V", binder);
		} else skip_ = true;
	}
	setAllowUnload(skip_);
}

void
Context::OnNativeForkAndSpecializePost(JNIEnv *env) {
	const JUTFString process_name(env, nice_name_);
	auto binder = skip_ ? ScopedLocalRef<jobject>{env, nullptr}
						: Service::instance()->RequestBinder(env, nice_name_);
	if (binder) {
		InstallInlineHooks();
		LoadDex(env);
		Init(env);
		LOGD("Done prepare");
		FindAndCall(env, "forkAndSpecializePost",
					"(Ljava/lang/String;Ljava/lang/String;Landroid/os/IBinder;)V",
					app_data_dir_, nice_name_,
					binder);
		LOGD("injected xposed into %s", process_name.get());
		setAllowUnload(false);
	} else {
		auto context = Context::ReleaseInstance();
		auto service = Service::ReleaseInstance();
		art_img.reset();
		LOGD("skipped %s", process_name.get());
		setAllowUnload(true);
	}
}
```
在ForkSystemServerPost和ForkAndSpecializePost函数时会触发inlinehook的操作
```c
void InstallInlineHooks() {
	if (installed.exchange(true)) [[unlikely]] {
		LOGD("Inline hooks have been installed, skip");
		return;
	}
	LOGD("Start to install inline hooks");
	const auto &handle_libart = *art_img;
	if (!handle_libart.isValid()) {
		LOGE("Failed to fetch libart.so");
	}
	art::Runtime::Setup(handle_libart);
	art::hidden_api::DisableHiddenApi(handle_libart);
	art::art_method::Setup(handle_libart);
	art::Thread::Setup(handle_libart);
	art::ClassLinker::Setup(handle_libart);
	art::mirror::Class::Setup(handle_libart);
	art::JNIEnvExt::Setup(handle_libart);
	art::instrumentation::DisableUpdateHookedMethodsCode(handle_libart);
	art::thread_list::ScopedSuspendAll::Setup(handle_libart);
	art::gc::ScopedGCCriticalSection::Setup(handle_libart);
	art::jit::jit_code_cache::Setup(handle_libart);
	art_img.reset();
	LOGD("Inline hooks installed");
}
```
主要是对libart.so的修改，以art::instrumentation::DisableUpdateHookedMethodsCode(handle_libart);为例
```c
// core/src/main/cpp/main/include/art/runtime/instrumentation.h

namespace art {
	namespace instrumentation {

		CREATE_MEM_HOOK_STUB_ENTRIES(
				"_ZN3art15instrumentation15Instrumentation21UpdateMethodsCodeImplEPNS_9ArtMethodEPKv",
				void, UpdateMethodsCode, (void * thiz, void * art_method, const void *quick_code), {
					if (lspd::isHooked(art_method)) [[unlikely]] {
						LOGD("Skip update method code for hooked method %s",
								art_method::PrettyMethod(art_method).c_str());
						return;
					} else {
						backup(thiz, art_method, quick_code);
					}
				});

		inline void DisableUpdateHookedMethodsCode(const SandHook::ElfImg &handle) {
			lspd::HookSym(handle, UpdateMethodsCode);
		}
	}
}

// core/src/main/cpp/main/include/base/object.h
inline static bool HookSym(H &&handle, T &arg) {
	auto original = Dlsym(std::forward<H>(handle), arg.sym);
	return HookSymNoHandle(original, arg);
}

inline static bool HookSymNoHandle(void *original, T &arg) {
	if (original) {
		if constexpr(is_instance<decltype(arg.backup), MemberFunction>::value) {
			void *backup;
			HookFunction(original, reinterpret_cast<void *>(arg.replace), &backup);
			arg.backup = reinterpret_cast<typename decltype(arg.backup)::FunType>(backup);
		} else {
			HookFunction(original, reinterpret_cast<void *>(arg.replace),
							reinterpret_cast<void **>(&arg.backup));
		}
		return true;
	} else {
		return false;
	}
}

inline int HookFunction(void *original, void *replace, void **backup) {
	_make_rwx(original, _page_size);
	if constexpr (isDebug) {
		Dl_info info;
		if (dladdr(original, &info))
			LOGD("Hooking %s (%p) from %s (%p)",
					info.dli_sname ? info.dli_sname : "(unknown symbol)", info.dli_saddr,
					info.dli_fname ? info.dli_fname : "(unknown file)", info.dli_fbase);
	}
	return DobbyHook(original, replace, backup);
}
```
这个版本的lsposed所使用到的inlinehook还是基于dobby hook来做的，而dobby hook是很典型的inline hook套路，基于指令的跳转，因此对于libart.so会增加额外的代码段与数据段
#### 2 frida maps特征
来源于[[原创]关于frida检测的一个新思路
](https://bbs.kanxue.com/thread-268586-1.htm)
### 四、对抗思路
- 复用riru_hide
	具体流程可参考之前的文章-[Riru原理理解](https://tcc0lin.github.io/riru%E5%8E%9F%E7%90%86%E7%90%86%E8%A7%A3/#21-hidepreparemapshidelibrary)，原理是将对应每个segment对应内存的数据替换，并去除文件关联
- open重定向
	例如内核层修改函数do_sys_open，返回指定伪装文件的fd来做展示，需要注意的是maps内容是随时变动的，那么伪装文件的生成也需要每次动态生成
- 内核层修改展示函数show_map_vma
	代码可参考[task_mmu.c](https://github.com/tcc0lin/KernelModification/blob/main/task_mmu.c)，修改展示内容
