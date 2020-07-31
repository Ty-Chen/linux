# 中断

### 一. 前言

  在前面的文章里，我们多次见到了中断的作用，如任务调度，系统调用从用户态陷入内核，文件系统的读写操作等。本文就Linux的中断机制进行较为全面的剖析。

### 二. 什么是中断

  中断通常被定义为改变处理器执行指令的顺序的一个事件，该事件与CPU芯片内外部硬件电路产生的电信号相对应。中断通常分为同步中断和异步中断：

* 同步中断\(synchronous\)：又称异常（exception），在指令执行时由CPU控制单元产生，之所以称之为同步，是因为只有在一条指令终止执行后CPU才会发出中断。
* 异步中断\(asynchronous\)：即通常所说的中断（interrupt\)，由其他硬件设备依照CPU时钟信号随机产生。

  从另一个角度来说，我们可以把中断分为外部或者硬件引起的中断以及软件引起的中断两种。外部中断，由 `Local APIC` 或者与 `Local APIC` 连接的处理器针脚接收。第二种类型 - 软件引起的中断，由处理器自身的特殊情况引起\(有时使用特殊架构的指令\)。一个常见的关于特殊情况的例子就是 除零，另一个例子就是使用 系统调用（`syscall`）。假设每一个物理硬件都有一根中断线，设备可以通过它对 CPU 发起中断信号，中断信号先通过一个控制器，然后发到CPU上执行。比较原始的设备中，中断信号发送给 [PIC](http://en.wikipedia.org/wiki/Programmable_Interrupt_Controller) ，它是一个顺序处理各种设备的各种中断请求的芯片。而现在通用的则是[高级程序中断控制器（Advanced Programmable Interrupt Controller）](https://en.wikipedia.org/wiki/Advanced_Programmable_Interrupt_Controller)做这件事情，即我们熟知的 `APIC`。一个 APIC 包括两个独立的设备：

* `Local APIC`
* `I/O APIC`

第一个设备 - `Local APIC`存在于每个CPU核心中，`Local APIC` 负责处理特定于 CPU 的中断配置，常被用于管理来自 APIC 时钟（APIC-timer）、热敏元件和其他与 I/O 设备连接的设备的中断。

第二个设备 - `I/O APIC` 提供了多核处理器的中断管理。它被用来在所有的 CPU 核心中分发外部中断。

一个中断的发生流程如下：

* 外部设备给中断控制器发送物理中断信号
* 中断控制器将物理中断信号转换成为中断向量 `interrupt vector`，发给各个 CPU
* 每个 CPU 都会有一个中断向量表，根据 `interrupt vector` 调用一个 IRQ 处理函数
* IRQ 处理函数中，将 `interrupt vector` 转化为抽象中断层的中断信号 `irq`，调用中断信号 `irq` 对应的中断描述结构（IDT）里面的 `irq_handler_t`

![img](https://static001.geekbang.org/resource/image/dd/13/dd492efdcf956cb22ce3d51592cdc113.png)

### 三. 中断结构体

  对于每一个中断，我们都有一个对应的描述结构体`irq_desc`，其中包括了众多描述该中断特点的成员变量，这里尤其需要强调描述该中断对应的全部动作的变量`struct irqaction *action`。

```text
struct irq_desc {
    struct irq_common_data  irq_common_data;
    struct irq_data     irq_data;
    unsigned int __percpu   *kstat_irqs;
    irq_flow_handler_t  handle_irq;
......
    struct irqaction    *action;    /* IRQ action list */
......
    int         parent_irq;
    struct module       *owner;
    const char      *name;
} ____cacheline_internodealigned_in_smp;
```

  每一个中断处理动作的结构 `struct irqaction`，都有以下成员：

* 中断处理函数 `handler`
* 设备 id`void *dev_id`
* 中断信号`irq`
* 如果中断处理函数在单独的线程运行，则有 `thread_fn` 是线程的执行函数，`thread` 是线程的 `task_struct`。

  一连串的动作通过链表的形式组合起来构成了该中断的所有动作。

```text
/**
 * struct irqaction - per interrupt action descriptor
 * @handler:    interrupt handler function
 * @name:   name of the device
 * @dev_id: cookie to identify the device
 * @percpu_dev_id:  cookie to identify the device
 * @next:   pointer to the next irqaction for shared interrupts
 * @irq:    interrupt number
 * @flags:  flags (see IRQF_* above)
 * @thread_fn:  interrupt handler function for threaded interrupts
 * @thread: thread pointer for threaded interrupts
 * @secondary:  pointer to secondary irqaction (force threading)
 * @thread_flags:   flags related to @thread
 * @thread_mask:    bitmask for keeping track of @thread activity
 * @dir:    pointer to the proc/irq/NN/name entry
 */
struct irqaction {
    irq_handler_t       handler;
    void            *dev_id;
    void __percpu       *percpu_dev_id;
    struct irqaction    *next;
    irq_handler_t       thread_fn;
    struct task_struct  *thread;
    struct irqaction    *secondary;
    unsigned int        irq;
    unsigned int        flags;
    unsigned long       thread_flags;
    unsigned long       thread_mask;
    const char      *name;
    struct proc_dir_entry   *dir;
} ____cacheline_internodealigned_in_smp;
```

  众多的中断`irq_desc`则采取类似于内存管理中所用到的基数树radix tree的方式进行管理。这种结构对于从某个整型 key 找到 value 速度很快，中断信号 `irq` 是这个整数。通过它，我们很快就能定位到对应的 `irq_desc`。

```text
#ifdef CONFIG_SPARSE_IRQ
static RADIX_TREE(irq_desc_tree, GFP_KERNEL);
struct irq_desc *irq_to_desc(unsigned int irq)
{
    return radix_tree_lookup(&irq_desc_tree, irq);
}
#else /* !CONFIG_SPARSE_IRQ */
struct irq_desc irq_desc[NR_IRQS] __cacheline_aligned_in_smp = {
    [0 ... NR_IRQS-1] = {
    }
};
struct irq_desc *irq_to_desc(unsigned int irq)
{
    return (irq < NR_IRQS) ? irq_desc + irq : NULL;
}
#endif /* !CONFIG_SPARSE_IRQ */
```

### 四. 中断流程

  我们从 CPU 收到中断向量开始分析.CPU收到的中断向量定义于[`irq_vectors.h`](https://code.woboq.org/linux/linux/arch/x86/include/asm/irq_vectors.h.html)。下面这一段是该头文件的注释，详细描述了IRQ向量的基本信息：

* 单个CPU拥有256（8位）IDT，即能处理256个中断，定义为`NR_VECTORS`
* CPU处理的中断分为几类
  * 0到31位为系统陷入或者异常，这些属于无法屏蔽的中断，必须进行处理
  * 32到127位为设备中断
  * 128位即我们常说的int80系统调用中断
  * 129至`INVALIDATE_TLB_VECTOR_START`也用来保存设备中断
  * `INVALIDATE_TLB_VECTOR_START`至255作为特殊中断
* 64位架构下每个CPU有独立的IDT表，而32位则共享一张表

```text
/*
 * Linux IRQ vector layout.
 *
 * There are 256 IDT entries (per CPU - each entry is 8 bytes) which can
 * be defined by Linux. They are used as a jump table by the CPU when a
 * given vector is triggered - by a CPU-external, CPU-internal or
 * software-triggered event.
 *
 * Linux sets the kernel code address each entry jumps to early during
 * bootup, and never changes them. This is the general layout of the
 * IDT entries:
 *
 *  Vectors   0 ...  31 : system traps and exceptions - hardcoded events
 *  Vectors  32 ... 127 : device interrupts
 *  Vector  128         : legacy int80 syscall interface
 *  Vectors 129 ... INVALIDATE_TLB_VECTOR_START-1 except 204 : device interrupts
 *  Vectors INVALIDATE_TLB_VECTOR_START ... 255 : special interrupts
 *
 * 64-bit x86 has per CPU IDT tables, 32-bit has one shared IDT table.
 *
 * This file enumerates the exact layout of them:
 */
#define IRQ_MOVE_CLEANUP_VECTOR     FIRST_EXTERNAL_VECTOR
#define IA32_SYSCALL_VECTOR     0x80
#define NR_VECTORS 256
#define FIRST_SYSTEM_VECTOR NR_VECTORS
```

  在[前文](https://ty-chen.github.io/linux-kernel-zero-process/#more)中有分析内核的开始源于`start_kernel()`，而中断部分则开始于其中的`trap_init()`，这里会填写IDT描述符构成中断向量表

```text
void __init trap_init(void)
{
    /* Init cpu_entry_area before IST entries are set up */
    setup_cpu_entry_areas();
    idt_setup_traps();
    /*
     * Set the IDT descriptor to a fixed read-only location, so that the
     * "sidt" instruction will not leak the location of the kernel, and
     * to defend the IDT against arbitrary memory write vulnerabilities.
     * It will be reloaded in cpu_init() */
    cea_set_pte(CPU_ENTRY_AREA_RO_IDT_VADDR, __pa_symbol(idt_table),
            PAGE_KERNEL_RO);
    idt_descr.address = CPU_ENTRY_AREA_RO_IDT;
    /*
     * Should be a barrier for any external CPU state:
     */
    cpu_init();
    idt_setup_ist_traps();
    x86_init.irqs.trap_init();
    idt_setup_debugidt_traps();
}
```

  在`idt_setup_traps()`中会初始化中断，其中前32个中断以枚举形式定义在`arch/x86/include/asm/traps.h`中

```text
/* Interrupts/Exceptions */
enum {
    X86_TRAP_DE = 0,    /*  0, Divide-by-zero */
    X86_TRAP_DB,        /*  1, Debug */
    X86_TRAP_NMI,       /*  2, Non-maskable Interrupt */
    X86_TRAP_BP,        /*  3, Breakpoint */
    X86_TRAP_OF,        /*  4, Overflow */
    X86_TRAP_BR,        /*  5, Bound Range Exceeded */
    X86_TRAP_UD,        /*  6, Invalid Opcode */
    X86_TRAP_NM,        /*  7, Device Not Available */
    X86_TRAP_DF,        /*  8, Double Fault */
    X86_TRAP_OLD_MF,    /*  9, Coprocessor Segment Overrun */
    X86_TRAP_TS,        /* 10, Invalid TSS */
    X86_TRAP_NP,        /* 11, Segment Not Present */
    X86_TRAP_SS,        /* 12, Stack Segment Fault */
    X86_TRAP_GP,        /* 13, General Protection Fault */
    X86_TRAP_PF,        /* 14, Page Fault */
    X86_TRAP_SPURIOUS,  /* 15, Spurious Interrupt */
    X86_TRAP_MF,        /* 16, x87 Floating-Point Exception */
    X86_TRAP_AC,        /* 17, Alignment Check */
    X86_TRAP_MC,        /* 18, Machine Check */
    X86_TRAP_XF,        /* 19, SIMD Floating-Point Exception */
    X86_TRAP_IRET = 32, /* 32, IRET Exception */
};
```

  `idt_setup_traps()`实际调用`idt_setup_from_table()`，其参数为两个默认中断向量表，值和上面枚举值相同。

```text
/**
 * idt_setup_traps - Initialize the idt table with default traps
 */
void __init idt_setup_traps(void)
{
    idt_setup_from_table(idt_table, def_idts, ARRAY_SIZE(def_idts), true);
}
​
/*
 * The exceptions which use Interrupt stacks. They are setup after
 * cpu_init() when the TSS has been initialized.
 */
static const __initconst struct idt_data ist_idts[] = {
    ISTG(X86_TRAP_DB,   debug,      DEBUG_STACK),
    ISTG(X86_TRAP_NMI,  nmi,        NMI_STACK),
    ISTG(X86_TRAP_DF,   double_fault,   DOUBLEFAULT_STACK),
#ifdef CONFIG_X86_MCE
    ISTG(X86_TRAP_MC,   &machine_check, MCE_STACK),
#endif
};
​
/*
 * The default IDT entries which are set up in trap_init() before
 * cpu_init() is invoked. Interrupt stacks cannot be used at that point and
 * the traps which use them are reinitialized with IST after cpu_init() has
 * set up TSS.
 */
static const __initconst struct idt_data def_idts[] = {
    INTG(X86_TRAP_DE,       divide_error),
    INTG(X86_TRAP_NMI,      nmi),
    INTG(X86_TRAP_BR,       bounds),
    INTG(X86_TRAP_UD,       invalid_op),
    INTG(X86_TRAP_NM,       device_not_available),
    INTG(X86_TRAP_OLD_MF,       coprocessor_segment_overrun),
    INTG(X86_TRAP_TS,       invalid_TSS),
    INTG(X86_TRAP_NP,       segment_not_present),
    INTG(X86_TRAP_SS,       stack_segment),
    INTG(X86_TRAP_GP,       general_protection),
    INTG(X86_TRAP_SPURIOUS,     spurious_interrupt_bug),
    INTG(X86_TRAP_MF,       coprocessor_error),
    INTG(X86_TRAP_AC,       alignment_check),
    INTG(X86_TRAP_XF,       simd_coprocessor_error),
#ifdef CONFIG_X86_32
    TSKG(X86_TRAP_DF,       GDT_ENTRY_DOUBLEFAULT_TSS),
#else
    INTG(X86_TRAP_DF,       double_fault),
#endif
    INTG(X86_TRAP_DB,       debug),
#ifdef CONFIG_X86_MCE
    INTG(X86_TRAP_MC,       &machine_check),
#endif
    SYSG(X86_TRAP_OF,       overflow),
#if defined(CONFIG_IA32_EMULATION)
    SYSG(IA32_SYSCALL_VECTOR,   entry_INT80_compat),
#elif defined(CONFIG_X86_32)
    SYSG(IA32_SYSCALL_VECTOR,   entry_INT80_32),
#endif
};
```

  在 `start_kernel()` 调用完毕 `trap_init()` 之后，还会调用 `init_IRQ()` 来初始化其他的设备中断，最终会调用到 `native_init_IRQ()`。这里面从第 32 个中断开始，到最后 `NR_VECTORS` 为止，对于 `used_vectors` 中没有标记为 1 的位置，都会调用 `set_intr_gate()` 设置中断向量表。`used_vectors` 中没有标记为 1 的，都是设备中断的部分，也即所有的设备中断的中断处理函数在中断向量表里面都会设置为从 `irq_entries_start` 开始，偏移量为 `i - FIRST_EXTERNAL_VECTOR` 的一项。

```text
void __init init_IRQ(void)
{
    int i;
    /*
     * On cpu 0, Assign ISA_IRQ_VECTOR(irq) to IRQ 0..15.
     * If these IRQ's are handled by legacy interrupt-controllers like PIC,
     * then this configuration will likely be static after the boot. If
     * these IRQ's are handled by more mordern controllers like IO-APIC,
     * then this vector space can be freed and re-used dynamically as the
     * irq's migrate etc.
     */
    for (i = 0; i < nr_legacy_irqs(); i++)
        per_cpu(vector_irq, 0)[ISA_IRQ_VECTOR(i)] = irq_to_desc(i);
    x86_init.irqs.intr_init();
}   
​
.irqs = {
    .pre_vector_init    = init_ISA_irqs,
    .intr_init      = native_init_IRQ,
    .trap_init      = x86_init_noop,
    .intr_mode_init     = apic_intr_mode_init
},
​
void __init native_init_IRQ(void)
{
    /* Execute any quirks before the call gates are initialised: */
    x86_init.irqs.pre_vector_init();
    idt_setup_apic_and_irq_gates();
    lapic_assign_system_vectors();
    if (!acpi_ioapic && !of_ioapic && nr_legacy_irqs())
        setup_irq(2, &irq2);
    irq_ctx_init(smp_processor_id());
}
```

  中断处理函数定义在 `irq_entries_start` 表里，在 `arch\x86\entry\entry_32.S` 和 `arch\x86\entry\entry_64.S` 都能找到这个函数表的定义。这里面定义了 `FIRST_SYSTEM_VECTOR` 到 `FIRST_EXTERNAL_VECTOR` 项。每一项都是中断处理函数，会跳到 `common_interrupt()` 去执行，并最终调用 `do_IRQ()`，调用完毕后，就从中断返回。

```text
ENTRY(irq_entries_start)
    vector=FIRST_EXTERNAL_VECTOR
    .rept (FIRST_SYSTEM_VECTOR - FIRST_EXTERNAL_VECTOR)
  pushl  $(~vector+0x80)      /* Note: always in signed byte range */
    vector=vector+1
  jmp  common_interrupt /* 会调用到do_IRQ */
  .align  8
    .endr
END(irq_entries_start)


common_interrupt:
  ASM_CLAC
  addq  $-0x80, (%rsp)      /* Adjust vector to [-256, -1] range */
  interrupt do_IRQ
  /* 0(%rsp): old RSP */
ret_from_intr:
......
  /* Interrupt came from user space */
GLOBAL(retint_user)
......
/* Returning to kernel space */
retint_kernel:
......
```

  `do_IRQ()`从 AX 寄存器里面拿到了中断向量 vector，但是别忘了中断控制器发送给每个 CPU 的中断向量都是每个 CPU 局部的，而抽象中断处理层的虚拟中断信号 `irq` 以及它对应的中断描述结构 `irq_desc` 是全局的，也即这个 CPU 的 200 号的中断向量和另一个 CPU 的 200 号中断向量对应的虚拟中断信号 `irq` 和中断描述结构 `irq_desc` 可能不一样，这就需要一个映射关系。这个映射关系放在 `Per CPU` 变量 `vector_irq` 里面。

```text
/*
 * do_IRQ handles all normal device IRQ's (the special
 * SMP cross-CPU interrupts have their own specific
 * handlers).
 */
__visible unsigned int __irq_entry do_IRQ(struct pt_regs *regs)
{
    struct pt_regs *old_regs = set_irq_regs(regs);
    struct irq_desc * desc;
    /* high bit used in ret_from_ code  */
    unsigned vector = ~regs->orig_ax;
......
    desc = __this_cpu_read(vector_irq[vector]);
    if (!handle_irq(desc, regs)) {
......
  }
......
    set_irq_regs(old_regs);
    return 1;
}

DECLARE_PER_CPU(vector_irq_t, vector_irq);
```

  在系统初始化的时候，我们会调用 `__assign_irq_vector()`，将虚拟中断信号 `irq` 分配到某个 CPU 上的中断向量。一旦找到某个向量，就调用`irq_to_desc(irq)`将 CPU 此向量对应的向量描述结构 `irq_desc`设置为虚拟中断信号 `irq` 对应的向量描述结构 。 `do_IRQ()` 会根据中断向量 vector 得到对应的 中断`irq`，然后调用 `handle_irq()`。`handle_irq()` 会调用 `generic_handle_irq_desc()`，最终调用 该中断`irq`绑定的处理函数 `handle_irq()`。

```text
bool handle_irq(struct irq_desc *desc, struct pt_regs *regs)
{
......
    generic_handle_irq_desc(desc);
......
}

/*
 * Architectures call this to let the generic IRQ layer
 * handle an interrupt.
 */
static inline void generic_handle_irq_desc(struct irq_desc *desc)
{
    desc->handle_irq(desc);
}
```

  `handle_irq()`函数最终会调用`__handle_irq_event_percpu()`，`__handle_irq_event_percpu()` 里面调用了 `irq_desc ()`里每个 ha`n`der，这些 `hander` 是我们在所有 `action` 列表中注册的，这才是我们设置的那个中断处理函数。如果返回值是 `IRQ_HANDLED`，就说明处理完毕；如果返回值是 `IRQ_WAKE_THREAD` 就唤醒线程。至此，中断的整个过程就结束了。

```text
irqreturn_t __handle_irq_event_percpu(struct irq_desc *desc, unsigned int *flags)
{
    irqreturn_t retval = IRQ_NONE;
    unsigned int irq = desc->irq_data.irq;
    struct irqaction *action;

    record_irq_time(desc);

    for_each_action_of_desc(desc, action) {
        irqreturn_t res;
        res = action->handler(irq, action->dev_id);
        switch (res) {
        case IRQ_WAKE_THREAD:
            __irq_wake_thread(desc, action);
        case IRQ_HANDLED:
            *flags |= action->flags;
            break;
        default:
            break;
        }
        retval |= res;
    }
    return retval;
}
```

### 总结

  本文大致分析了中断的整个流程，由此我们可以了解到中断结构体，注册机制以及如何生效并触发对应的中断处理函数。

### 源码资料

\[1\] [irq\_desc](https://code.woboq.org/linux/linux/include/linux/irqdesc.h.html#irq_desc)

\[2\] [trap\_init\(\)](https://code.woboq.org/linux/linux/arch/x86/kernel/traps.c.html#trap_init)

\[3\] [init\_IRQ\(\)](https://code.woboq.org/linux/linux/arch/x86/kernel/irqinit.c.html#init_IRQ)

### 参考资料

\[1\] wiki

\[2\] [elixir.bootlin.com/linux](https://elixir.bootlin.com/linux/v5.7-rc1/source)

\[3\] [woboq](https://code.woboq.org/)

\[4\] Linux-insides

\[5\] 深入理解Linux内核

\[6\] Linux内核设计的艺术

\[7\] 极客时间 趣谈Linux操作系统

\[8\] Linux设备驱动程序

