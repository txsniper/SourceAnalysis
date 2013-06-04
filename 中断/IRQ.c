
/**********************************************************************************
 *                                  中断处理过程
 *
 **********************************************************************************/

778 /*
     * 当CPU穿越中断门时，是自动关闭中断的 
779  * Build the entry stubs and pointer table with some assembler magic.
780  * We pack 7 stubs into a single 32-byte chunk, which will fit in a
781  * single cache line on all modern x86 implementations.
782  */
783 .section .init.rodata,"a"
784 ENTRY(interrupt)
785 .section .entry.text, "ax"
786         .p2align 5
787         .p2align CONFIG_X86_L1_CACHE_SHIFT
788 ENTRY(irq_entries_start)
789         RING0_INT_FRAME
790 vector=FIRST_EXTERNAL_VECTOR
791 .rept (NR_VECTORS-FIRST_EXTERNAL_VECTOR+6)/7
792         .balign 32
793   .rept 7
794     .if vector < NR_VECTORS
795       .if vector <> FIRST_EXTERNAL_VECTOR
796         CFI_ADJUST_CFA_OFFSET -4
797       .endif
798 1:      pushl_cfi $(~vector+0x80)       /* Note: always in signed byte range */
799       .if ((vector-FIRST_EXTERNAL_VECTOR)%7) <> 6
800         jmp 2f
801       .endif
802       .previous
803         .long 1b
804       .section .entry.text, "ax"
805 vector=vector+1
806     .endif
807   .endr
808 2:      jmp common_interrupt
809 .endr
810 END(irq_entries_start)
811 
812 .previous
813 END(interrupt)
814 .previous
815 
816 /*
817  * the CPU automatically disables interrupts when executing an IRQ vector,
818  * so IRQ-flags tracing has to follow that:
819  */
820         .p2align CONFIG_X86_L1_CACHE_SHIFT
821 common_interrupt:
822         ASM_CLAC
823         addl $-0x80,(%esp)      /* Adjust vector into the [-256,-1] range */
824         SAVE_ALL
825         TRACE_IRQS_OFF
826         movl %esp,%eax
            /* 这里调用do_IRQ处理中断 */
827         call do_IRQ
828         jmp ret_from_intr
829 ENDPROC(common_interrupt)
830         CFI_ENDPROC
831 


176 /*
177  * do_IRQ handles all normal device IRQ's (the special
178  * SMP cross-CPU interrupts have their own specific
179  * handlers).
180  */
181 unsigned int __irq_entry do_IRQ(struct pt_regs *regs)
182 {
            /* set_irq_regs先保存原来的寄存器集合，然后设定新的寄存器集合*/
183         struct pt_regs *old_regs = set_irq_regs(regs);
184 
185         /* high bit used in ret_from_ code  */
186         unsigned vector = ~regs->orig_ax;
187         unsigned irq;
188 
189         irq_enter();
190         exit_idle();
191 
192         irq = __this_cpu_read(vector_irq[vector]);
193 
194         if (!handle_irq(irq, regs)) {
195                 ack_APIC_irq();
196 
197                 if (printk_ratelimit())
198                         pr_emerg("%s: %d.%d No irq handler for vector (irq %d)\n",
199                                 __func__, smp_processor_id(), vector, irq);
200         }
201 
202         irq_exit();
203 
204         set_irq_regs(old_regs);
205         return 1;
206 }

 21 static inline struct pt_regs *set_irq_regs(struct pt_regs *new_regs)
 22 {
 23         struct pt_regs *old_regs;
 24 
 25         old_regs = get_irq_regs();
 26         this_cpu_write(irq_regs, new_regs);
 27 
 28         return old_regs;
 29 }

302 /*
303  * Enter an interrupt context.
304  */
305 void irq_enter(void)
306 {
307         int cpu = smp_processor_id();
308         /* 
             *  rcu_irq_enter - inform RCU that current CPU is entering irq away from idle
             *  Just as with spinlocks, RCU readers are not permitted to block,  switch 
             *  to user-mode execution, or enter the idle loop.
             *  详细见RCU文档
             */ 
309         rcu_irq_enter();
            /* idle进程会停止周期时钟
             * 中断发生于周期时钟停止期间，如果不做任何处理，中断服务程序中如果要访问jiffies计数值，
             * 可能得到一个滞后的jiffies值，因为正常状态下，jiffies值会在恢复周期时钟时正确地更新，
             * 所以，为了防止这种情况发生，在进入中断的irq_enter期间，tick_check_idle会被调用：
             */
310         if (is_idle_task(current) && !in_interrupt()) {
311                 /*
312                  * Prevent raise_softirq from needlessly waking up ksoftirqd
313                  * here, as softirq will be serviced on return from interrupt.
314                  */
315                 local_bh_disable();
316                 tick_check_idle(cpu);
317                 _local_bh_enable();
318         }
319 
320         __irq_enter();
321 }

148 /*
149  * It is safe to do non-atomic ops on ->hardirq_context,
150  * because NMI handlers may not preempt and the ops are
151  * always balanced, so the interrupted value of ->hardirq_context
152  * will always be restored.
153  */
    /* add_preempt_count(HARDIRQ_OFFSET)
     * preempt_count变量的HARDIRQ部分+1，即标识一个hardirq的上下文，
     * 所以可以认为do_IRQ()调用irq_enter函数 意味着中断处理进入hardirq阶段。
     */
154 #define __irq_enter()                                   \
155         do {                                            \
156                 vtime_account_irq_enter(current);       \
157                 add_preempt_count(HARDIRQ_OFFSET);      \
158                 trace_hardirq_enter();                  \
159         } while (0)
160 


   /* 回到do_IRQ，接下来分析exit_idle */
293 static void __exit_idle(void)
294 {
            /* 若当前CPU不是idle状态，则退出 */
295         if (x86_test_and_clear_bit_percpu(0, is_idle) == 0)
296                 return;
            /* 通知idle内核通知链：IDLE_END*/
297         atomic_notifier_call_chain(&idle_notifier, IDLE_END, NULL);
298 }
299 
300 /* Called from interrupts to signify idle end */
301 void exit_idle(void)
302 {
303         /* idle loop has pid 0 */
            /* idle 进程的pid为0，因此若当前进程非idle进程，则退出*/
304         if (current->pid)
305                 return;
306         __exit_idle();
307 }

    /* 回到do_IRQ，继续调用handle_irq */

183 bool handle_irq(unsigned irq, struct pt_regs *regs)
184 {
185         struct irq_desc *desc;
186         int overflow;
187         /* 
             * Debugging check for stack overflow: 
             * is there less than 1KB free? 
             */
188         overflow = check_stack_overflow();
189 
190         desc = irq_to_desc(irq);
191         if (unlikely(!desc))
192                 return false;
193         /* 
             * user_mode_vm用来检测regs是否来自用户态，若来自用户态，则不用切换栈,
             * 则直接执行desc->handle_irq
             * 详细见 user mode interrupt
             * [PATCH] x86-32: don't switch to irq stack for a user-mode irq
             */
            /*
             * 通用中断子系统的原型最初出现于ARM体系中，一开始内核的开发者
             * 们把3种中断类型区分出来，他们是：

                     电平触发中断（level type）
                     边缘触发中断（edge type）
                     简易的中断（simple type）

             * 后来又针对某些需要回应eoi（end of interrupt）的中断控制器，
             * 加入了fast eoi type，针对smp加入了per cpu type。
             * 
             *  desc->handle_irq将调用用户注册设备驱动时设置的处理函数
             *  例如：下面是一个驱动的初始化函数，其中将handle_irq设置为
             *  handle_level_irq，即为电平触发中断
             *  int __init s5p_init_irq_eint(void)
                {
                    int irq;
                    for (irq = IRQ_EINT(0); irq <= IRQ_EINT(15); irq++)
                       irq_set_chip(irq, &s5p_irq_vic_eint);
                    for (irq = IRQ_EINT(16); irq <= IRQ_EINT(31); irq++) 
                    {
                       irq_set_chip_and_handler(irq, &s5p_irq_eint, handle_level_irq);
                       set_irq_flags(irq, IRQF_VALID);
                    }
                    irq_set_chained_handler(IRQ_EINT16_31, s5p_irq_demux_eint16_31);
                    return 0; 
             */
194         if (user_mode_vm(regs) || !execute_on_irq_stack(overflow, desc, irq)) {
195                 if (unlikely(overflow))
196                         print_stack_overflow();
197                 desc->handle_irq(irq, desc);
198         }
199 
200         return true;
201 }

    /* 内核执行必须切换到IRQ栈 */
 80 static inline int
 81 execute_on_irq_stack(int overflow, struct irq_desc *desc, int irq)
 82 {
 83         union irq_ctx *curctx, *irqctx;
 84         u32 *isp, arg1, arg2;
 85         /*
             *  curctx是当前栈，可以通过current_thread_info()求出，
             *  thread_info实例与当前栈在一个union中  
             *  irqctx是IRQ栈
             */  
 86         curctx = (union irq_ctx *) current_thread_info();
 87         irqctx = __this_cpu_read(hardirq_ctx);
 88 
 89         /*
 90          * this is where we switch to the IRQ stack. However, if we are
 91          * already using the IRQ stack (because we interrupted a hardirq
 92          * handler) we can't do that and just have to keep using the
 93          * current stack (which is the irq stack already after all)
 94          */
            /*
             *  若当前栈已经是IRQ栈，则退出
             */
 95         if (unlikely(curctx == irqctx))
 96                 return 0;
 97 
 98         /* build the stack frame on the IRQ stack */
            /* 创建IRQ栈 */
            /* isp为IRQ栈esp */
 99         isp = (u32 *) ((char *)irqctx + sizeof(*irqctx));
100         irqctx->tinfo.task = curctx->tinfo.task;
101         irqctx->tinfo.previous_esp = current_stack_pointer;
102 
103         /* Copy the preempt_count so that the [soft]irq checks work. */
104         irqctx->tinfo.preempt_count = curctx->tinfo.preempt_count;
105 
106         if (unlikely(overflow))
107                 call_on_stack(print_stack_overflow, isp);
108         /* 切换到IRQ栈，然后执行desc->handle_irq，执行完后切换回当前栈*/
109         asm volatile("xchgl     %%ebx,%%esp     \n"
110                      "call      *%%edi          \n"
111                      "movl      %%ebx,%%esp     \n"
112                      : "=a" (arg1), "=d" (arg2), "=b" (isp)
113                      :  "" (irq),   "1" (desc),  "2" (isp),
114                         "D" (desc->handle_irq)
115                      : "memory", "cc", "ecx");
116         return 1;
117 }

/* 执行完handle_irq，返回ture，接下来执行do_IRQ中的irq_exit() */

339 /*
340  * Exit an interrupt context. Process softirqs if needed and possible:
341  */
342 void irq_exit(void)
343 {
344         vtime_account_irq_exit(current);
345         trace_hardirq_exit();
            /* preempt_count变量的HARDIRQ部分-1，目的是清除hardirq的上下文标记 */
346         sub_preempt_count(IRQ_EXIT_OFFSET);
            /*
             * 根据in_interrupt的定义来看，Linux内核认为HARDIRQ、SOFTIRQ以
             * 及NMI 都属于interrupt范畴..."，所以softirq部分是否被执行，取决
             * 于：1.当前是否在中断上下文，2. 是否有pending的softirq需要处理。
             * 第一个条件，主要用来防止softirq部分的重入，因为一旦有pending的
             * softirq需要处理，调用invoke_softirq()
             */
347         if (!in_interrupt() && local_softirq_pending())
348                 invoke_softirq();
349 
350 #ifdef CONFIG_NO_HZ
351         /* Make sure that timer wheel updates are propagated */
352         if (idle_cpu(smp_processor_id()) && !in_interrupt() && !need_resched())
353                 tick_nohz_irq_exit();
354 #endif
355         rcu_irq_exit();
356         sched_preempt_enable_no_resched();
357 }


    /* 各种中断类型的处理函数 */
360 /**   一.电平中断
361  *      handle_level_irq - Level type irq handler
362  *      @irq:   the interrupt number
363  *      @desc:  the interrupt description structure for this irq
364  *
365  *      Level type interrupts are active as long as the hardware line has
366  *      the active level. This may require to mask the interrupt and unmask
367  *      it after the associated handler has acknowledged the device, so the
368  *      interrupt line is back to inactive.
369  */
370 void
371 handle_level_irq(unsigned int irq, struct irq_desc *desc)
372 {
           /*
            *  这里锁住描述符的自旋锁，有两个原因:
            *    1. 其他核可能同时收到了中断，将所有同一中断号的中断交给同一个CPU处理，
            * 可以避免ISR中做复杂的同步。这个原因是由于unix系统历史原因造成的。
            *    2. 其他核可能在调用request_irq等函数注册ISR，需要使用该锁保护desc中的数据不被破坏。
            * 注意:这里使用的是raw_spin_lock而不是spin_lock，因为实时内核中，spin_lock已经可以睡眠了。
            * 而目前处于硬中断中，不能睡眠。
            */ 
373         raw_spin_lock(&desc->lock);
            /* mask_ack_irq屏蔽当前中断线并且确认IRQ，通过调用chip->mask_ack */
374         mask_ack_irq(desc);
375         /* 通过检查IRQ_INPROGRESS标志来判断当前IRQ是否在另一个CPU
             * 上运行，若是，则退出
             * 虽然本函数处于中断描述符的lock锁保护之中，但是
             * handle_irq_event函数在调用ISR时，会将锁打开。
             * 也就是说，其他核在处理ISR时，本核可能进入锁保护的代码中来。
             * */
376         if (unlikely(irqd_irq_inprogress(&desc->irq_data)))
377                 if (!irq_check_poll(desc))
378                         goto out_unlock;
379         /*
             * IRQS_REPLAY标志是为了挽救丢失的中断。这个几乎不会碰上，暂时不深入分析这个标志。
             * 运行到此，中断已经在处理了，就不必考虑挽救丢失的中断了。
             * IRQS_WAITING标志表示初始化进程正在等待中断的到来，当探测一些老式设备时，驱动用此方法确定硬件产生的中断号。
             * 比如一些老式的鼠标、键盘、ISA设备需要这么做。它们不是PCI设备，必须用中断探测的方法确定其中断号。
             * 当然，运行到这里，可以将IRQS_WAITING标志去除了，以通知初始化函数，相应的中断号已经触发。
             */ 
380         desc->istate &= ~(IRQS_REPLAY | IRQS_WAITING);
            /*
             * 记录下中断在本CPU上触发的次数、本CPU总中断次数。在/proc中要用到这些统计值
             */ 
381         kstat_incr_irqs_this_cpu(irq, desc);
382 
383         /*
384          * If its disabled or no action available
385          * keep it masked and get out of here
386          */
387         if (unlikely(!desc->action || irqd_irq_disabled(&desc->irq_data))) {
388                 desc->istate |= IRQS_PENDING;
389                 goto out_unlock;
390         }
391         /*
             * handle_irq_event要么是在中断上下文调用ISR，要么是唤醒处理线程处理中断。
             * 注意:这个函数会临时打开中断描述符的自旋锁。
             */
392         handle_irq_event(desc);
393 
394         cond_unmask_irq(desc);
395 
396 out_unlock:
397         raw_spin_unlock(&desc->lock);
398 }
399 EXPORT_SYMBOL_GPL(handle_level_irq)
/*
 *  handle_irq_event
 */
182 irqreturn_t handle_irq_event(struct irq_desc *desc)
183 {
184         struct irqaction *action = desc->action;
185         irqreturn_t ret;
186         /*
             *     清除挂起标志。当本核正在调用ISR的过程中，如果发生了同样的中断，
             * 那么其他核在收到中断时，会发现本核将IRQD_IRQ_INPROGRESS设置到描述符中。
             * 那么其他核会设置IRQS_PENDING并退出。本核在处理完ISR后，会判断此标志并重
             * 新执行ISR，在重新执行ISR前，应当将IRQS_PENDING标志清除。
             */  
187         desc->istate &= ~IRQS_PENDING;
            /*
             *  在释放自旋锁前，设置IRQD_IRQ_INPROGRESS标志，表示本核正在处理该中断。
             *  其他核不应当再处理同样的中断。
             */
188         irqd_set(&desc->irq_data, IRQD_IRQ_INPROGRESS);
189         raw_spin_unlock(&desc->lock);
190 
191         ret = handle_irq_event_percpu(desc, action);
192 
193         raw_spin_lock(&desc->lock);
194         irqd_clear(&desc->irq_data, IRQD_IRQ_INPROGRESS);
195         return ret;
196 }

132 irqreturn_t
133 handle_irq_event_percpu(struct irq_desc *desc, struct irqaction *action)
134 {
            /* retval表示中断处理结果，默认设置为IRQ_NONE表示该中断没有被ISR响应 */
135         irqreturn_t retval = IRQ_NONE;
136         unsigned int flags = 0, irq = desc->irq_data.irq;
137         /* 这里的循环是遍历ISR链表，循环调用ISR处理函数 */
138         do {
139                 irqreturn_t res;
140 
141                 trace_irq_handler_entry(irq, action);
142                 res = action->handler(irq, action->dev_id);
143                 trace_irq_handler_exit(irq, action, res);
144                 /*
                     * 老版本的内核会根据ISR注册时的标志，在中断处理函数中将中断打开或者关闭。
                     * 新版本内核应当是完全实现了中断线程化，长时间运行的中断ISR放到线程中去了，
                     * 也就是说，在中断上下文都应当是关中断运行。
                     * 这里的警告应当是找出那些不符合新版本要求的ISR，在这里打印警告，并强制将中断关闭。
                     */   
145                 if (WARN_ONCE(!irqs_disabled(),"irq %u handler %pF enabled interrupts\n",
146                               irq, action->handler))
147                         local_irq_disable();
148 
149                 switch (res) {
150                 case IRQ_WAKE_THREAD:
151                         /*
152                          * Catch drivers which return WAKE_THREAD but
153                          * did not set up a thread function
154                          */
155                         if (unlikely(!action->thread_fn)) {
156                                 warn_no_thread(irq, action);
157                                 break;
158                         }
159 
160                         irq_wake_thread(desc, action);
161 
162                         /* Fall through to add to randomness */
163                 case IRQ_HANDLED:
                            /*  将所有ISR标志取或，只要其中一个ISR有
                             *  IRQF_SAMPLE_RANDOM标志，就将本中断作为一个中断源
                             */
164                         flags |= action->flags;
165                         break;
166 
167                 default:
168                         break;
169                 }
170                 /*
                     * 将所有ISR的返回值取或，那么，只要有一个返回了IRQ_HANDLED，
                     * 上层都会认为中断得到了正确的处理。  
                     */  
171                 retval |= res;
172                 action = action->next;
173         } while (action);
174         /*  如果本中断是一个随机源，则处理随机种子 */
175         add_interrupt_randomness(irq, flags);
176 
177         if (!noirqdebug)
178                 note_interrupt(irq, desc, retval);
179         return retval;
180 }
181 

342 /*
343  * Called unconditionally from handle_level_irq() and only for oneshot
344  * interrupts from handle_fasteoi_irq()
345  */
346 static void cond_unmask_irq(struct irq_desc *desc)
347 {
348         /*
349          * We need to unmask in the following cases:
350          * - Standard level irq (IRQF_ONESHOT is not set)
351          * - Oneshot irq which did not wake the thread (caused by a
352          *   spurious interrupt or a primary handler handling it
353          *   completely).
354          */
355         if (!irqd_irq_disabled(&desc->irq_data) &&
356             irqd_irq_masked(&desc->irq_data) && !desc->threads_oneshot)
357                 unmask_irq(desc);
358 }


 
