/*
 *  kprobe源码分析：
 *  1. kprobe的初始化：
 *      init_kprobes: 主要完成三个任务：
 *     （1）.初始化存储kprobes的哈希表。
 *     （2）.初始化kprobe的blacklist，blacklist是一个黑名单，其中的内核地址是
             kprobe不应该探测的，例如与中断相关的函数地址。由于内核将内核符号的
			 地址导出到/proc/kallsyms（内核符号表），因此可以利用kallsyms相关函
			 数查找地址。
 *	   （3）.调用特定体系结构的初始化函数（arch_init_kprobes）。
 *	   （4）.注册异常通知链，register_die_notifier用于注册异常信号（int 3，debug）
             的处理函数kprobe_exceptions_notify，kprobe通过处理异常信号实现被调试
			 者与调试者之间的交互。register_module_notifier用于检测探测kprobe探测
			 的地址是否位于模块中，并且检查探测的地址是否合法。

 *  2. kprobe的注册：register_kprobe
       主要完成的任务是将探测点的指令保存到kprobe结构中，然后将探测点的指令替换为 
	   INT 3（代码中的BREAKPOINT_INSTRUCTION），然后等待运行时发生INT 3异常。

 *  3. kprobe的处理流程：
       对于kprobe功能的实现主要利用了内核中的两个功能特性：异常（尤其是int 3），单
 	   步执行（EFLAGS中的TF标志）。
 *      大概的流程：
 *     （1）在注册探测点的时候，对被探测函数的指令码进行替换，替换为int 3的指令码；
 *     （2）在执行int 3的异常执行中，通过通知链的方式调用kprobe的异常处理函数
            kprobe_exceptions_notify；
 *     （3）在kprobe_exceptions_notify中，判断发生的异常类型（INT 3 or DEBUG or GPF），
            然后调用相应的处理函数：
		       （3.1）. INT 3（说明执行到了探测点）：
		            调用kprobe_handler，首先检查kprobe是否存在用户注册的pre_handler函
					      数，存在则执行，用户注册的pre_handler一般返回0。执行完后，准备进
					      入单步调试，调用setup_singlestep，通过设置EFLAGS中的TF标志位，并
					      且把异常返回的地址修改为保存的原指令码。代码返回，执行原有指令，
					      执行结束后触发单步异常，处理过程如下3.2；
		       （3.2）. DEBUG（说明触发了单步异常）: 
		            调用post_kprobe_handler，该函数执行恢复工作，比如寄存器和EFLAGS，
					      然后执行用户注册的post_handler，然后清除单步标志，并最后返回。
		       （3.3）. GPF（说明执行过程中发生了错误，触发了保护性异常）：
		                执行kprobe_fault_handler，然后返回。
 *     
 */
/* KPROBE状态*/
46	/* kprobe_status settings */
47	#define KPROBE_HIT_ACTIVE	0x00000001 /* 仅收到INT 3异常通知，还没有开始设定单步异常*/
48	#define KPROBE_HIT_SS		0x00000002 /* 收到 DEBUG异常通知，正在处理单步异常过程中，还未处理完*/
49	#define KPROBE_REENTER		0x00000004 /* 第一次还未处理完，再次进入INT 3异常*/
50	#define KPROBE_HIT_SSDONE	0x00000008 /* 单步异常处理完成*/

/kernel/kprobes.c
2062 static int __init init_kprobes(void)
2063 {
2064         int i, err = 0;
2065         unsigned long offset = 0, size = 0;
2066         char *modname, namebuf[128];
2067         const char *symbol_name;
2068         void *addr;
2069         struct kprobe_blackpoint *kb;
2070 
2071         /* FIXME allocate the probe table, currently defined statically */
2072         /* initialize all list heads */
             /*   static struct hlist_head kprobe_table[KPROBE_TABLE_SIZE];            */
             /*   static struct hlist_head kretprobe_inst_table[KPROBE_TABLE_SIZE];    */
             /*   kprobe_table和kretprobe_inst_table：kprobe_table 是 kprobes 方法的表头, */
             /*   kretprobe_inst_table 是返回回调函数的表头                               */

2073         for (i = 0; i < KPROBE_TABLE_SIZE; i++) {
2074                 INIT_HLIST_HEAD(&kprobe_table[i]);
2075                 INIT_HLIST_HEAD(&kretprobe_inst_table[i]);
2076                 raw_spin_lock_init(&(kretprobe_table_locks[i].lock));
2077         }
2078 
2079         /*
2080          * Lookup and populate the kprobe_blacklist.
2081          *
2082          * Unlike the kretprobe blacklist, we'll need to determine
2083          * the range of addresses that belong to the said functions,
2084          * since a kprobe need not necessarily be at the beginning
2085          * of a function.
2086          */
             /*
              *通过kprobe_blacklist和kretprobe_blacklist中的符号名得出
              *它们的地址，这两个blacklist中存储着不应该使用kprobe和kretprobe
              *进行探测的地址，比如与中断相关
              */
2087         for (kb = kprobe_blacklist; kb->name != NULL; kb++) {
2088                 kprobe_lookup_name(kb->name, addr);
2089                 if (!addr)
2090                         continue;
2091 
2092                 kb->start_addr = (unsigned long)addr;
2093                 symbol_name = kallsyms_lookup(kb->start_addr,
2094                                 &size, &offset, &modname, namebuf);
2095                 if (!symbol_name)
2096                         kb->range = 0;
2097                 else
2098                         kb->range = size;
2099         }
2100 
2101         if (kretprobe_blacklist_size) {
2102                 /* lookup the function address from its name */
2103                 for (i = 0; kretprobe_blacklist[i].name != NULL; i++) {
2104                         kprobe_lookup_name(kretprobe_blacklist[i].name,
2105                                            kretprobe_blacklist[i].addr);
2106                         if (!kretprobe_blacklist[i].addr)
2107                                 printk("kretprobe: lookup failed: %s\n",
2108                                        kretprobe_blacklist[i].name);
2109                 }
2110         }
2111 
2112 #if defined(CONFIG_OPTPROBES)
2113 #if defined(__ARCH_WANT_KPROBES_INSN_SLOT)
2114         /* Init kprobe_optinsn_slots */
2115         kprobe_optinsn_slots.insn_size = MAX_OPTINSN_SIZE;
2116 #endif
2117         /* By default, kprobes can be optimized */
2118         kprobes_allow_optimization = true;
2119 #endif
2120 
2121         /* By default, kprobes are armed */
2122         kprobes_all_disarmed = false;
2123         /*调用特定体系结构中的初始化函数*/
2124         err = arch_init_kprobes();

             /*
              *注册通知链，register_die_notifier(&kprobe_exceptions_nb)
              *用于注册异常通知链，kprobe 的实现在要探测的位置插入一个异
              *常指令(X86上是int 3），当触发这个异常时，将执行kprobe_exceptions_nb
              *中的回调函数。register_module_notifier(&kprobe_module_nb)注册 
              *一个回调函数，用于在模块栽入时检测kprobe探测的模块中地址是否正确                    
              */
2125         if (!err)
2126                 err = register_die_notifier(&kprobe_exceptions_nb);
2127         if (!err)
2128                 err = register_module_notifier(&kprobe_module_nb);
2129 
2130         kprobes_initialized = (err == 0);
2131 
2132         if (!err)
2133                 init_test_probes();
2134         return err;
2135 }
     
	 /*
      *   arch_init_kprobes()在X86上将调用kprobes-opt.c中的arch_init_optprobes函数,
	  *   该函数分配的buffer和parameter array用于X86底层对kprobe的实现。
      *   374 #define MAX_OPTIMIZE_PROBES 256
      *   375 static struct text_poke_param *jump_poke_params;
      *   376 static struct jump_poke_buffer {
      *   377         u8 buf[RELATIVEJUMP_SIZE];
      *   378 } *jump_poke_bufs;
      *   229 struct text_poke_param {
      *   230         void *addr;
      *   231         const void *opcode;
      *   232         size_t len;
      *   233 };
	  *   
	  */
495 int __kprobes arch_init_optprobes(void)
496 {
497         /* Allocate code buffer and parameter array */
498         jump_poke_bufs = kmalloc(sizeof(struct jump_poke_buffer) *
499                                  MAX_OPTIMIZE_PROBES, GFP_KERNEL);
500         if (!jump_poke_bufs)
501                 return -ENOMEM;
502 
503         jump_poke_params = kmalloc(sizeof(struct text_poke_param) *
504                                    MAX_OPTIMIZE_PROBES, GFP_KERNEL);
505         if (!jump_poke_params) {
506                 kfree(jump_poke_bufs);
507                 jump_poke_bufs = NULL;
508                 return -ENOMEM;
509         }
510 
511         return 0;
512 }

1689 static struct notifier_block kprobe_exceptions_nb = {
1690         .notifier_call = kprobe_exceptions_notify,
              /*
               * 优先级最高，保证最先执行
               */
1691         .priority = 0x7fffffff /* we need to be notified first */
1692 };

2057 static struct notifier_block kprobe_module_nb = {
2058         .notifier_call = kprobes_module_callback,
2059         .priority = 0
2060 };

     /*
      *  kprobes_module_callback检查探测模块的kprobe，
      *  确保探测的模块中的地址符合要求，否则将kill_kprobe
      */
2018 /* Module notifier call back, checking kprobes on the module */
2019 static int __kprobes kprobes_module_callback(struct notifier_block *nb,
2020                                              unsigned long val, void *data)

967 int __kprobes
968 kprobe_exceptions_notify(struct notifier_block *self, unsigned long val, void *data)
969 {
970         struct die_args *args = data;
971         int ret = NOTIFY_DONE;
972         
            /*
             * user_mode_vm 检测args->regs是否属于用户空间
             */
973         if (args->regs && user_mode_vm(args->regs))
974                 return ret;
975 
976         switch (val) {
            /*
             * INT 3中断，则调用kprobe_handler
             */
977         case DIE_INT3:
978                 if (kprobe_handler(args->regs))
979                         ret = NOTIFY_STOP;
980                 break;
            /*
             * DIE_DEBUG说明发生了debug异常，由于之前开启了单步调试模式，
             * 执行完指令后会触发异常DIE_DEBUG
             */
981         case DIE_DEBUG:
982                 if (post_kprobe_handler(args->regs)) {
983                         /*
984                          * Reset the BS bit in dr6 (pointed by args->err) to
985                          * denote completion of processing
986                          */
                            /*
                             * 若post_kprobe_handler返回1，则设置dr6调试寄存器标志
                             * 表示这个探测过程的完成
                             */
987                         (*(unsigned long *)ERR_PTR(args->err)) &= ~DR_STEP;
988                         ret = NOTIFY_STOP;
989                 }
990                 break;
            /*
             * DIE_GPF说明执行过程中发生了错误，触发了保护性异常，将执行
             * 注册的kprobe_fault_handler
             */
991         case DIE_GPF:
992                 /*
993                  * To be potentially processing a kprobe fault and to
994                  * trust the result from kprobe_running(), we have
995                  * be non-preemptible.
996                  */
997                 if (!preemptible() && kprobe_running() &&
998                     kprobe_fault_handler(args->regs, args->trapnr))
999                         ret = NOTIFY_STOP;
1000                 break;
1001         default:
1002                 break;
1003         }
1004         return ret;
1005 }

    /*
     * 先来分析kprobe_handler
     */

561 /*
562  * Interrupts are disabled on entry as trap3 is an interrupt gate and they
563  * remain disabled throughout this function.
564  */
565 static int __kprobes kprobe_handler(struct pt_regs *regs)
566 {
567         kprobe_opcode_t *addr;
568         struct kprobe *p;
569         struct kprobe_ctlblk *kcb;
570         /*
             *  addr为发生INT 3中断的地址  
             */
571         addr = (kprobe_opcode_t *)(regs->ip - sizeof(kprobe_opcode_t));
572         /*
573          * We don't want to be preempted for the entire
574          * duration of kprobe processing. We conditionally
575          * re-enable preemption at the end of this function,
576          * and also in reenter_kprobe() and setup_singlestep().
577          */
578         preempt_disable();
579         /*
             * 得到当前CPU上的kprobe_ctlblk，通过地址addr得到对应的kprobe
             */
580         kcb = get_kprobe_ctlblk();
581         p = get_kprobe(addr);
582 
583         if (p) {
                    /*
                     *  开始检查此次 int3 异常是否是由前一次 Kprobes 处理
                     *  流程引发的，如果是由前一次Kprobes处理流程引发，
                     *  则有两种可能性：
                     *  1.该次Kprobes处理由于前一次回调函数执行了被探
                     *  测代码造成的（比如探测点在printk函数中，而我们在注
                     *  册的回调函数中又调用了printk)。
                     *  2.是由于 jprobe造成的，jprobe_return()将产生 int3
                     *  异常。
                     */
584                 if (kprobe_running()) {
585                         if (reenter_kprobe(p, regs, kcb))
586                                 return 1;
587                 } else {
                      /*
                       *  set_current_kprobe设置当前CPU上的kprobe为p，并且保存
                       *  当前regs->flags中的X86_EFLAGS_TF和X86_EFLAGS_IF位
                       *  X86_EFLAGS_TF置位则表明单步执行
                       *  X86_EFLAGS_IF置位则表明允许中断
                       */
588                         set_current_kprobe(p, regs, kcb);
589                         kcb->kprobe_status = KPROBE_HIT_ACTIVE;
590 
591                         /*
592                          * If we have no pre-handler or it returned 0, we
593                          * continue with normal processing.  If we have a
594                          * pre-handler and it returned non-zero, it prepped
595                          * for calling the break_handler below on re-entry
596                          * for jprobe processing, so get out doing nothing
597                          * more here.
598                          */
                        /*
                         *  若有pre_handler或者pre_handler返回0则设置单步执行
                         *  模式，为post_handler执行做准备
                         */
599                         if (!p->pre_handler || !p->pre_handler(p, regs))
600                                 setup_singlestep(p, regs, kcb, 0);
601                         return 1;
602                 }
603         } else if (*addr != BREAKPOINT_INSTRUCTION) {
604                 /*
605                  * The breakpoint instruction was removed right
606                  * after we hit it.  Another cpu has removed
607                  * either a probepoint or a debugger breakpoint
608                  * at this address.  In either case, no further
609                  * handling of this interrupt is appropriate.
610                  * Back up over the (now missing) int3 and run
611                  * the original instruction.
612                  */
613                 regs->ip = (unsigned long)addr;
614                 preempt_enable_no_resched();
615                 return 1;
616         } else if (kprobe_running()) {
                    /*
                     * 目前有kprobe正在运行，而此时产生异常的地址并没有被
                     * 注册过，于是可以断定是由jprobe_return函数触发INT3异
                     * 常引起的
                     */
617                 p = __this_cpu_read(current_kprobe);
618                 if (p->break_handler && p->break_handler(p, regs)) {
619 #ifdef KPROBES_CAN_USE_FTRACE
620                         if (kprobe_ftrace(p)) {
621                                 skip_singlestep(p, regs, kcb);
622                                 return 1;
623                         }
624 #endif
625                         setup_singlestep(p, regs, kcb, 0);
626                         return 1;
627                 }
628         } /* else: not a kprobe fault; let the kernel handle it */
629 
630         preempt_enable_no_resched();
631         return 0;
632 }

/*
 * setup_singlestep
 */
472 static void __kprobes
473 setup_singlestep(struct kprobe *p, struct pt_regs *regs, struct kprobe_ctlblk *kcb, int reenter)
474 {
            /*
             *  若regs->flags标志KPROBE_FLAG_OPTIMIZED没有置位，则setup_detour_execution
             *  返回0
             */
475         if (setup_detour_execution(p, regs, reenter))
476                 return;
477         /*
             * 若没有定义CONFIG_PREEMPT编译选项，则表明内核不支持抢占
             */
478 #if !defined(CONFIG_PREEMPT)
479         if (p->ainsn.boostable == 1 && !p->post_handler) {
480                 /* Boost up -- we can execute copied instructions directly */
481                 if (!reenter)
482                         reset_current_kprobe();
483                 /*
484                  * Reentering boosted probe doesn't reset current_kprobe,
485                  * nor set current_kprobe, because it doesn't use single
486                  * stepping.
487                  */
488                 regs->ip = (unsigned long)p->ainsn.insn;
489                 preempt_enable_no_resched();
490                 return;
491         }
492 #endif
            /*
             * jprobe_return()产生的INT 3，reenter == 1
             */
493         if (reenter) {
494                 save_previous_kprobe(kcb);
495                 set_current_kprobe(p, regs, kcb);
496                 kcb->kprobe_status = KPROBE_REENTER;
497         } else
498                 kcb->kprobe_status = KPROBE_HIT_SS;
499         /* Prepare real single stepping */
            /*
             * clear_btf()用途还不清楚
             * 设置EFLAGS的TF标志位，清除IF标志位（禁止中断）
             */
500         clear_btf();
501         regs->flags |= X86_EFLAGS_TF;
502         regs->flags &= ~X86_EFLAGS_IF;
503         /* single step inline if the instruction is an int3 */
            /*
             * 因为我们替换了探测点的第一个字节，这个字节保存在opcode中，
			 * 如果探测点原来的指令就是 INT 3，
             */
504         if (p->opcode == BREAKPOINT_INSTRUCTION)
505                 regs->ip = (unsigned long)p->addr;
506         else
507                 regs->ip = (unsigned long)p->ainsn.insn;
508 }


864 /*
865  * Interrupts are disabled on entry as trap1 is an interrupt 
     * gate and they remain disabled throughout this function.
867  */
868 static int __kprobes post_kprobe_handler(struct pt_regs *regs)
869 {
870         struct kprobe *cur = kprobe_running();
871         struct kprobe_ctlblk *kcb = get_kprobe_ctlblk();
872 
873         if (!cur)
874                 return 0;
875         /*
             * 恢复寄存器，并且根据单步执行的指令对IP进行修正
             */
876         resume_execution(cur, regs, kcb);
            /*
             *  恢复异常执行前的EFLAGS
             */
877         regs->flags |= kcb->kprobe_saved_flags;
878         /*
             *  执行注册的post_handler  
             */
879         if ((kcb->kprobe_status != KPROBE_REENTER) && cur->post_handler) {
880                 kcb->kprobe_status = KPROBE_HIT_SSDONE;
881                 cur->post_handler(cur, regs, 0);
882         }
883 
884         /* Restore back the original saved kprobes variables and continue. */
885         if (kcb->kprobe_status == KPROBE_REENTER) {
886                 restore_previous_kprobe(kcb);
887                 goto out;
888         }
889         reset_current_kprobe();
890 out:
891         preempt_enable_no_resched();
892 
893         /*
894          * if somebody else is singlestepping across a probe point, flags
895          * will have TF set, in which case, continue the remaining processing
896          * of do_debug, as if this is not a probe hit.
897          */
898         if (regs->flags & X86_EFLAGS_TF)
899                 return 0;
900 
901         return 1;
902 }


760	/*
761	 * Called after single-stepping.  p->addr is the address of the
762	 * instruction whose first byte has been replaced by the "int 3"
763	 * instruction.  To avoid the SMP problems that can occur when we
764	 * temporarily put back the original opcode to single-step, we
765	 * single-stepped a copy of the instruction.  The address of this
766	 * copy is p->ainsn.insn.
767	 *
768	 * This function prepares to return from the post-single-step
769	 * interrupt.  We have to fix up the stack as follows:
770	 *
771	 * 0) Except in the case of absolute or indirect jump or call instructions,
772	 * the new ip is relative to the copied instruction.  We need to make
773	 * it relative to the original instruction.
774	 *
775	 * 1) If the single-stepped instruction was pushfl, then the TF and IF
776	 * flags are set in the just-pushed flags, and may need to be cleared.
777	 *
778	 * 2) If the single-stepped instruction was a call, the return address
779	 * that is atop the stack is the address following the copied instruction.
780	 * We need to make it the address following the original instruction.
781	 *
782	 * If this is the first time we've single-stepped the instruction at
783	 * this probepoint, and the instruction is boostable, boost it: add a
784	 * jump instruction after the copied instruction, that jumps to the next
785	 * instruction after the probepoint.
786	 */
/*
 *  resume_execution是在单步调试执行之后执行的，因此需要考虑单步执行的影响
 */
787	static void __kprobes
788	resume_execution(struct kprobe *p, struct pt_regs *regs, struct kprobe_ctlblk *kcb)
789	{
	    /* tos为栈的地址 */
790		unsigned long *tos = stack_addr(regs);
791		unsigned long copy_ip = (unsigned long)p->ainsn.insn;
792		unsigned long orig_ip = (unsigned long)p->addr;
793		kprobe_opcode_t *insn = p->ainsn.insn;
794	
795		/* Skip prefixes */
796		insn = skip_prefixes(insn);
797	    /* 关闭TF标志即关闭单步调试 */
798		regs->flags &= ~X86_EFLAGS_TF;
799		switch (*insn) {
800		case 0x9c:	/* pushfl */
	    /* 
		 * pushfl指令会将状态寄存器的内容压入堆栈保存，
		 * 由于我们要单步调试状态执行pushfl，所以会将
		 * TF和IF标志设置后执行pushfl，这样pushfl会将
		 * TF和IF标志状态保存到栈中，为消除调试的影响，
		 * 我们需要清除这两个标志，恢复正常的状态寄存
		 * 器
		 */
801			*tos &= ~(X86_EFLAGS_TF | X86_EFLAGS_IF);
802			*tos |= kcb->kprobe_old_flags;
803			break;
804		case 0xc2:	/* iret/ret/lret */
805		case 0xc3:
806		case 0xca:
807		case 0xcb:
808		case 0xcf:
809		case 0xea:	/* jmp absolute -- ip is correct */
810			/* ip is already adjusted, no more changes required */
811			p->ainsn.boostable = 1;
812			goto no_change;
813		case 0xe8:	/* call relative - Fix return addr */
814			*tos = orig_ip + (*tos - copy_ip);
815			break;
816	#ifdef CONFIG_X86_32
817		case 0x9a:	/* call absolute -- same as call absolute, indirect */
818			*tos = orig_ip + (*tos - copy_ip);
819			goto no_change;
820	#endif
821		case 0xff:
822			if ((insn[1] & 0x30) == 0x10) {
823				/*
824				 * call absolute, indirect
825				 * Fix return addr; ip is correct.
826				 * But this is not boostable
827				 */
828				*tos = orig_ip + (*tos - copy_ip);
829				goto no_change;
830			} else if (((insn[1] & 0x31) == 0x20) ||
831				   ((insn[1] & 0x31) == 0x21)) {
832				/*
833				 * jmp near and far, absolute indirect
834				 * ip is correct. And this is boostable
835				 */
836				p->ainsn.boostable = 1;
837				goto no_change;
838			}
839		default:
840			break;
841		}
842	
843		if (p->ainsn.boostable == 0) {
844			if ((regs->ip > copy_ip) &&
845			    (regs->ip - copy_ip) + 5 < MAX_INSN_SIZE) {
846				/*
847				 * These instructions can be executed directly if it
848				 * jumps back to correct address.
849				 */
850				synthesize_reljump((void *)regs->ip,
851					(void *)orig_ip + (regs->ip - copy_ip));
852				p->ainsn.boostable = 1;
853			} else {
854				p->ainsn.boostable = -1;
855			}
856		}
857	
858		regs->ip += orig_ip - copy_ip;
859	
860	no_change:
861		restore_btf();
862	}

/********************************************************************************************************
 ******************************************  注册 kprobe ************************************************
 ********************************************************************************************************
 */
1468 int __kprobes register_kprobe(struct kprobe *p)
1469 {
1470         int ret;
1471         struct kprobe *old_p;
1472         struct module *probed_mod;
1473         kprobe_opcode_t *addr;
1474 
1475         /* Adjust probe address from symbol */
             /* 获取探测点的地址*/
1476         addr = kprobe_addr(p);
1477         if (IS_ERR(addr))
1478                 return PTR_ERR(addr);
1479         p->addr = addr;
1480         
             /* 检查是否重复注册这个kprobe */
1481         ret = check_kprobe_rereg(p);
1482         if (ret)
1483                 return ret;
1484 
1485         /* User can pass only KPROBE_FLAG_DISABLED to register_kprobe */
             /* 初始化注册的kprobe结构*/
1486         p->flags &= KPROBE_FLAG_DISABLED;
1487         p->nmissed = 0;
1488         INIT_LIST_HEAD(&p->list);

1489         /* 检查探测点的地址是否合法，如果探测点位于模块中，返回模块的地址*/
1490         ret = check_kprobe_address_safe(p, &probed_mod);
1491         if (ret)
1492                 return ret;
1493 
1494         mutex_lock(&kprobe_mutex);
1495         
             /*
              * 检查探测点是否已经注册过kprobe，如果已经注册过，那么将
              * 探测同一个地址的kprobe结构用链表连接在一起
              */
1496         old_p = get_kprobe(p->addr);
1497         if (old_p) {
1498                 /* Since this may unoptimize old_p, locking text_mutex. */
1499                 ret = register_aggr_kprobe(old_p, p);
1500                 goto out;
1501         }
1502 
1503         mutex_lock(&text_mutex);        /* Avoiding text modification */
             /* 准备一个kprobe，将调用特定于体系结构的函数*/
1504         ret = prepare_kprobe(p);
1505         mutex_unlock(&text_mutex);
1506         if (ret)
1507                 goto out;
1508         /*将准备注册的kprobe添加到kprobe_table中*/
1509         INIT_HLIST_NODE(&p->hlist);
1510         hlist_add_head_rcu(&p->hlist,
1511                        &kprobe_table[hash_ptr(p->addr, KPROBE_HASH_BITS)]);
1512 
1513         if (!kprobes_all_disarmed && !kprobe_disabled(p))
             /* 将探测点的指令替换为int 3*/
1514                 arm_kprobe(p);
1515 
1516         /* Try to optimize kprobe */
1517         try_to_optimize_kprobe(p);
1518 
1519 out:
1520         mutex_unlock(&kprobe_mutex);
1521 
1522         if (probed_mod)
1523                 module_put(probed_mod);
1524 
1525         return ret;
1526 }
        /* kprobe_addr: 通过注册的kprobe获取探测点的地址。
		 * 在kprobe结构中，symbol_name表示符号名，我们可以通过符号名得出符号地址，
		 * addr也表示探测点所在的地址，因此，不能同时指定symbol_name和addr。
		 * 1. 若同时指定symbol_name和addr或者都不指定，则返回错误。
		 * 2. 若指定了symbol_name而没有指定addr，则通过symbol_name得出addr。
		 * 3. 若指定了addr而没有指定symbol_name，则沿用指定的addr。
		 * 4. 将addr加上offset(偏移)得出探测点的地址。(可以通过这种方式在一个函数
		 * 的offset偏移处探测。例如：探测printk函数的第三个字节开始的指令，那么
		 * offset为0x3)
		 *
		 */
1344	/*
1345	 * If we have a symbol_name argument, look it up and add the offset field
1346	 * to it. This way, we can specify a relative address to a symbol.
1347	 * This returns encoded errors if it fails to look up symbol or invalid
1348	 * combination of parameters.
1349	 */
1350	static kprobe_opcode_t __kprobes *kprobe_addr(struct kprobe *p)
1351	{
1352		kprobe_opcode_t *addr = p->addr;
1353	
1354		if ((p->symbol_name && p->addr) ||
1355		    (!p->symbol_name && !p->addr))
1356			goto invalid;
1357	
1358		if (p->symbol_name) {
1359			kprobe_lookup_name(p->symbol_name, addr);
1360			if (!addr)
1361				return ERR_PTR(-ENOENT);
1362		}
1363	
1364		addr = (kprobe_opcode_t *)(((char *)addr) + p->offset);
1365		if (addr)
1366			return addr;
1367	
1368	invalid:
1369		return ERR_PTR(-EINVAL);
1370	}

     /*
      *  检查kprobe结构是否重复注册涉及以下三个函数：
      *  check_kprobe_rereg， __get_valid_kprobe和get_kprobe
      */
1392	/* Return error if the kprobe is being re-registered */
1393	static inline int check_kprobe_rereg(struct kprobe *p)
1394	{
1395		int ret = 0;
1396	
1397		mutex_lock(&kprobe_mutex);
1398		if (__get_valid_kprobe(p))
1399			ret = -EINVAL;
1400		mutex_unlock(&kprobe_mutex);
1401	
1402		return ret;
1403	}

        /*
		 * 探测点地址相同的kprobe结构通过kprobe结构中的双向链表list相连
		 */
1372	/* Check passed kprobe is valid and return kprobe in kprobe_table. */
1373	static struct kprobe * __kprobes __get_valid_kprobe(struct kprobe *p)
1374	{
1375		struct kprobe *ap, *list_p;
1376	
1377		ap = get_kprobe(p->addr);
1378		if (unlikely(!ap))
1379			return NULL;
1380	
1381		if (p != ap) {
1382			list_for_each_entry_rcu(list_p, &ap->list, list)
1383				if (list_p == p)
1384				/* kprobe p is a valid probe */
1385					goto valid;
1386			return NULL;
1387		}
1388	valid:
1389		return ap;
1390	}

328	/*
329	 * This routine is called either:
330	 * 	- under the kprobe_mutex - during kprobe_[un]register()
331	 * 				OR
332	 * 	- with preemption disabled - from arch/xxx/kernel/kprobes.c
333	 */
    /*
	 * 首先根据地址获取kprobe_table中的哈希链表，然后遍历，找到探测点
	 * 地址相同的结点
	 */
334	struct kprobe __kprobes *get_kprobe(void *addr)
335	{
336		struct hlist_head *head;
337		struct hlist_node *node;
338		struct kprobe *p;
339	
340		head = &kprobe_table[hash_ptr(addr, KPROBE_HASH_BITS)];
341		hlist_for_each_entry_rcu(p, node, head, hlist) {
342			if (p->addr == addr)
343				return p;
344		}
345	
346		return NULL;
347	}

        /* 如果探测点上已经有了其他的kprobe，则调用 register_aggr_kprobe*/
1247	/*
1248	 * This is the second or subsequent kprobe at the address - handle
1249	 * the intricacies
1250	 */
1251	static int __kprobes register_aggr_kprobe(struct kprobe *orig_p,
1252						  struct kprobe *p)
1253	{
1254		int ret = 0;
1255		struct kprobe *ap = orig_p;
1256	
1257		/* For preparing optimization, jump_label_text_reserved() is called */
1258		jump_label_lock();
1259		/*
1260		 * Get online CPUs to avoid text_mutex deadlock.with stop machine,
1261		 * which is invoked by unoptimize_kprobe() in add_new_kprobe()
1262		 */
	        /*
			 * 在与特定的CPU工作时，我们要确保CPU不被移除，增加引用计数
			 * 详情参考linux CPU热插拔
			 */
1263		get_online_cpus();
            /*
			 * 如果要优化kprobe，则可能修改内核代码，因此此处对内核代码加锁，
			 * 确保互斥访问
			 */
1264		mutex_lock(&text_mutex);
1265	
1266		if (!kprobe_aggrprobe(orig_p)) {
1267			/* If orig_p is not an aggr_kprobe, create new aggr_kprobe. */
	            /*
                  If there are multi kprobes on the same probepoint, there 
                  will be one extra aggr_kprobe on the head of kprobe list. 
                  The aggr_kprobe has aggr_post_handler/aggr_break_handler 
                  whether the other kprobe post_hander/break_handler is NULL 
                  or not. This patch modifies this, only when there is one or 
                  more kprobe in the list whose post_handler is not NULL, 
                  post_handler of aggr_kprobe will be set as aggr_post_handler. 
                */
1268			ap = alloc_aggr_kprobe(orig_p);
1269			if (!ap) {
1270				ret = -ENOMEM;
1271				goto out;
1272			}
                /*    init_aggr_kprobe
                 *   1232		ap->pre_handler = aggr_pre_handler;
                 *   1233		ap->fault_handler = aggr_fault_handler;
                 *   1234		   //We don't care the kprobe which has gone
                 *   1235		if (p->post_handler && !kprobe_gone(p))
                 *   1236			ap->post_handler = aggr_post_handler;
                 *   1237		if (p->break_handler && !kprobe_gone(p))
                 *   1238			ap->break_handler = aggr_break_handler;
				 */
1273			init_aggr_kprobe(ap, orig_p);
1274		} else if (kprobe_unused(ap))
1275			/* This probe is going to die. Rescue it */
1276			reuse_unused_kprobe(ap);
1277	    /*
               When module is freed(kprobes hooks module_notifier to get 
			   this event), kprobes which probe the functions in that module 
			   are set to "Gone" flag to the flags member. These "Gone" probes
               are never be enabled.
			 */
1278		if (kprobe_gone(ap)) {
1279			/*
1280			 * Attempting to insert new probe at the same location that
1281			 * had a probe in the module vaddr area which already
1282			 * freed. So, the instruction slot has already been
1283			 * released. We need a new slot for the new probe.
1284			 */
1285			ret = arch_prepare_kprobe(ap);
1286			if (ret)
1287				/*
1288				 * Even if fail to allocate new slot, don't need to
1289				 * free aggr_probe. It will be used next time, or
1290				 * freed by unregister_kprobe.
1291				 */
1292				goto out;
1293	
1294			/* Prepare optimized instructions if possible. */
1295			prepare_optimized_kprobe(ap);
1296	
1297			/*
1298			 * Clear gone flag to prevent allocating new slot again, and
1299			 * set disabled flag because it is not armed yet.
1300			 */
1301			ap->flags = (ap->flags & ~KPROBE_FLAG_GONE)
1302				    | KPROBE_FLAG_DISABLED;
1303		}
1304	
1305		/* Copy ap's insn slot to p */
1306		copy_kprobe(ap, p);
1307		ret = add_new_kprobe(ap, p);
1308	
1309	out:
1310		mutex_unlock(&text_mutex);
1311		put_online_cpus();
1312		jump_label_unlock();
1313	
1314		if (ret == 0 && kprobe_disabled(ap) && !kprobe_disabled(p)) {
1315			ap->flags &= ~KPROBE_FLAG_DISABLED;
1316			if (!kprobes_all_disarmed)
1317				/* Arm the breakpoint again. */
1318				arm_kprobe(ap);
1319		}
1320		return ret;
1321	}

735 /* Allocate new optimized_kprobe and try to prepare optimized instructions */
736 static __kprobes struct kprobe *alloc_aggr_kprobe(struct kprobe *p)
737 {
738         struct optimized_kprobe *op;
739 
740         op = kzalloc(sizeof(struct optimized_kprobe), GFP_KERNEL);
741         if (!op)
742                 return NULL;
743 
744         INIT_LIST_HEAD(&op->list);
745         op->kp.addr = p->addr;
746         arch_prepare_optimized_kprobe(op);
747 
748         return &op->kp;
749 }
750 

    /*
     *  [ PATCH -tip 0/6] kprobes: Kprobes jump optimization support
     */
285 #ifdef CONFIG_OPTPROBES
286 /*
287  * Internal structure for direct jump optimized probe
288  */
289 struct optimized_kprobe {
290         struct kprobe kp;
291         struct list_head list;  /* list for optimizing queue */
292         struct arch_optimized_insn optinsn;
293 };


319 /*
320  * Copy replacing target instructions
321  * Target instructions MUST be relocatable (checked inside)
322  * This is called when new aggr(opt)probe is allocated or reused.
323  */
324 int __kprobes arch_prepare_optimized_kprobe(struct optimized_kprobe *op)
325 {
326         u8 *buf;
327         int ret;
328         long rel;
329 
330         if (!can_optimize((unsigned long)op->kp.addr))
331                 return -EILSEQ;
332 
333         op->optinsn.insn = get_optinsn_slot();
334         if (!op->optinsn.insn)
335                 return -ENOMEM;
336 
337         /*
338          * Verify if the address gap is in 2GB range, because this uses
339          * a relative jump.
340          */
341         rel = (long)op->optinsn.insn - (long)op->kp.addr + RELATIVEJUMP_SIZE;
342         if (abs(rel) > 0x7fffffff)
343                 return -ERANGE;
344 
345         buf = (u8 *)op->optinsn.insn;
346 
347         /* Copy instructions into the out-of-line buffer */
348         ret = copy_optimized_instructions(buf + TMPL_END_IDX, op->kp.addr);
349         if (ret < 0) {
350                 __arch_remove_optimized_kprobe(op, 0);
351                 return ret;
352         }
353         op->optinsn.size = ret;
354 
355         /* Copy arch-dep-instance from template */
356         memcpy(buf, &optprobe_template_entry, TMPL_END_IDX);
357 
358         /* Set probe information */
359         synthesize_set_arg1(buf + TMPL_MOVE_IDX, (unsigned long)op);
360 
361         /* Set probe function call */
362         synthesize_relcall(buf + TMPL_CALL_IDX, optimized_callback);
363 
364         /* Set returning jmp instruction at the tail of out-of-line buffer */
365         synthesize_reljump(buf + TMPL_END_IDX + op->optinsn.size,
366                            (u8 *)op->kp.addr + op->optinsn.size);
367 
368         flush_icache_range((unsigned long) buf,
369                            (unsigned long) buf + TMPL_END_IDX +
370                            op->optinsn.size + RELATIVEJUMP_SIZE);
371         return 0;
372 }


229 /* Decode whole function to ensure any instructions don't jump into target */
    /*
     * Introduce x86 arch-specific optimization code, which supports both of
     * x86-32 and x86-64.
     *
     * This code also supports safety checking, which decodes whole of a function
     * in which probe is inserted, and checks following conditions before
     * optimization:
     *    - The optimized instructions which will be replaced by a jump instruction
            don't straddle the function boundary.
     *    - There is no indirect jump instruction, because it will jumps into
     *      the address range which is replaced by jump operand.
     *    - There is no jump/loop instruction which jumps into the address range
            which is replaced by jump operand. 
     */ 
230 static int __kprobes can_optimize(unsigned long paddr)
231 {
232         unsigned long addr, size = 0, offset = 0;
233         struct insn insn;
234         kprobe_opcode_t buf[MAX_INSN_SIZE];
235 
236         /* Lookup symbol including addr */
            /* size为符号的大小，offset为addr相对于符号起始地址的偏移*/
237         if (!kallsyms_lookup_size_offset(paddr, &size, &offset))
238                 return 0;
239 
240         /*
241          * Do not optimize in the entry code due to the unstable
242          * stack handling.
243          */
            /* 
             * 检查paddr不在内核的entry code中,__entry_text_start和
             * __entry_text_end由内核编译时链接工具导出
             */
244         if ((paddr >= (unsigned long)__entry_text_start) &&
245             (paddr <  (unsigned long)__entry_text_end))
246                 return 0;
247 
248         /* Check there is enough space for a relative jump. */
            /*
             *  相对跳转指令需要5个字节，若空间不够5个字节，则无法在paddr所在
             *  函数中插入相对跳转指令。
             */
            /*  38 #define RELATIVEJUMP_SIZE 5 */
249         if (size - offset < RELATIVEJUMP_SIZE)
250                 return 0;
251 
252         /* Decode instructions */
            /* addr为符号的起始地址 */
253         addr = paddr - offset;
254         while (addr < paddr - offset + size) { /* Decode until function end */
                    /* 判断addr是否在exception_table中，在循环中addr为函数中每条指令首地址 */
255                 if (search_exception_tables(addr))
256                         /*
257                          * Since some fixup code will jumps into this function,
258                          * we can't optimize kprobe in this function.
259                          */
260                         return 0;
                    /* recover_probed_instruction将探测之前的原始指令保存到buf中 */
                    /* 
                     * insn_init将insn.kaddr设置为recover_probed_instruction返回的地址，
                     * 若recover_probed_instruction操作成功，则返回buf，若失败，则返回
                     * addr。
                     */
261                 kernel_insn_init(&insn, (void *)recover_probed_instruction(buf, addr));
                    /* insn_get_length获取指令的长度 */
262                 insn_get_length(&insn);
263                 /* Another subsystem puts a breakpoint */
                    /* 如果原始指令第一个字节为一个断点，则返回 */
264                 if (insn.opcode.bytes[0] == BREAKPOINT_INSTRUCTION)
265                         return 0;
266                 /* Recover address */
                    /* 将insn.kaddr设置为指令的起始地址，next_byte设置为下一条指令起始地址 */
267                 insn.kaddr = (void *)addr;
268                 insn.next_byte = (void *)(addr + insn.length);
269                 /* Check any instructions don't jump into target */
                    /* 若addr*/
270                 if (insn_is_indirect_jump(&insn) ||
                        /* 
                         * 判断insn中保存的指令如果为跳转指令，则其跳转地址不在探测点
                         * 将要被替换的区域内，被替换的区域将包含一个间接跳转，因此有
                         * RELATIVE_ADDR_SIZE的长度
                         */
271                     insn_jump_into_range(&insn, paddr + INT3_SIZE,
272                                          RELATIVE_ADDR_SIZE))
273                         return 0;
                    /* addr指向下一条指令首地址 */
274                 addr += insn.length;
275         }
276 
277         return 1;
278 }


117 /* Init insn for kernel text */
118 static inline void kernel_insn_init(struct insn *insn, const void *kaddr)
119 {
120 #ifdef CONFIG_X86_64
121         insn_init(insn, kaddr, 1);
122 #else /* CONFIG_X86_32 */
123         insn_init(insn, kaddr, 0);
124 #endif
125 }

 47 /**
 48  * insn_init() - initialize struct insn
 49  * @insn:       &struct insn to be initialized
 50  * @kaddr:      address (in kernel memory) of instruction (or copy thereof)
 51  * @x86_64:     !0 for 64-bit kernel or 64-bit app
 52  */
 53 void insn_init(struct insn *insn, const void *kaddr, int x86_64)
 54 {
 55         memset(insn, 0, sizeof(*insn));
 56         insn->kaddr = kaddr;
 57         insn->next_byte = kaddr;
 58         insn->x86_64 = x86_64 ? 1 : 0;
 59         insn->opnd_bytes = 4;
 60         if (x86_64)
 61                 insn->addr_bytes = 8;
 62         else
 63                 insn->addr_bytes = 4;
 64 }

246 /*
247  * Recover the probed instruction at addr for further analysis.
248  * Caller must lock kprobes by kprobe_mutex, or disable preemption
249  * for preventing to release referencing kprobes.
250  */
251 unsigned long recover_probed_instruction(kprobe_opcode_t *buf, unsigned long addr)
252 {
253         unsigned long __addr;
254 
255         __addr = __recover_optprobed_insn(buf, addr);
            /* 
             * 若__addr != addr，则说明addr所在的kprobe是优化kprobe，并且将
             * 返回buf
             */
256         if (__addr != addr)
257                 return __addr;
258        /* 处理非优化的probe，若出错则返回addr */
259         return __recover_probed_insn(buf, addr);
260 }

 42 unsigned long __recover_optprobed_insn(kprobe_opcode_t *buf, unsigned long addr)
 43 {
 44         struct optimized_kprobe *op;
 45         struct kprobe *kp;
 46         long offs;
 47         int i;
 48 
 49         for (i = 0; i < RELATIVEJUMP_SIZE; i++) {
                    /* 检查以addr为结束地址的RELATIVEJUMP_SIZE内有没有优化kprobe */
 50                 kp = get_kprobe((void *)addr - i);
 51                 /* This function only handles jump-optimized kprobe */
 52                 if (kp && kprobe_optimized(kp)) {
 53                         op = container_of(kp, struct optimized_kprobe, kp);
 54                         /* If op->list is not empty, op is under optimizing */
 55                         if (list_empty(&op->list))
 56                                 goto found;
 57                 }
 58         }
 59 
 60         return addr;
 61 found:
 62         /*
 63          * If the kprobe can be optimized, original bytes which can be
 64          * overwritten by jump destination address. In this case, original
 65          * bytes must be recovered from op->optinsn.copied_insn buffer.
 66          */
 67         memcpy(buf, (void *)addr, MAX_INSN_SIZE * sizeof(kprobe_opcode_t));
            /* 若addr就是要探测的地址 */
 68         if (addr == (unsigned long)kp->addr) {
 69                 buf[0] = kp->opcode;
 70                 memcpy(buf + 1, op->optinsn.copied_insn, RELATIVE_ADDR_SIZE);
 71         } else {
 72                 offs = addr - (unsigned long)kp->addr - 1;
 73                 memcpy(buf, op->optinsn.copied_insn + offs, RELATIVE_ADDR_SIZE - offs);
 74         }
 75 
 76         return (unsigned long)buf;
 77 }
 78 

218 static unsigned long
219 __recover_probed_insn(kprobe_opcode_t *buf, unsigned long addr)
220 {
221         struct kprobe *kp;
222 
223         kp = get_kprobe((void *)addr);
224         /* There is no probe, return original address */
225         if (!kp)
226                 return addr;
227 
228         /*
229          *  Basically, kp->ainsn.insn has an original instruction.
230          *  However, RIP-relative instruction can not do single-stepping
231          *  at different place, __copy_instruction() tweaks the displacement of
232          *  that instruction. In that case, we can't recover the instruction
233          *  from the kp->ainsn.insn.
234          *
235          *  On the other hand, kp->opcode has a copy of the first byte of
236          *  the probed instruction, which is overwritten by int3. And
237          *  the instruction at kp->addr is not modified by kprobes except
238          *  for the first byte, we can recover the original instruction
239          *  from it and kp->opcode.
240          */
241         memcpy(buf, kp->addr, MAX_INSN_SIZE * sizeof(kprobe_opcode_t));
242         buf[0] = kp->opcode;
243         return (unsigned long)buf;
244 }
245 
 

194 /* Check whether insn is indirect jump */
195 static int __kprobes insn_is_indirect_jump(struct insn *insn)
196 {
197         return ((insn->opcode.bytes[0] == 0xff &&
198                 (X86_MODRM_REG(insn->modrm.value) & 6) == 4) || /* Jump */
199                 insn->opcode.bytes[0] == 0xea); /* Segment based jump */
200 }
201 
202 /* Check whether insn jumps into specified address range */
203 static int insn_jump_into_range(struct insn *insn, unsigned long start, int len)
204 {
205         unsigned long target = 0;
206 
207         switch (insn->opcode.bytes[0]) {
208         case 0xe0:      /* loopne */
209         case 0xe1:      /* loope */
210         case 0xe2:      /* loop */
211         case 0xe3:      /* jcxz */
212         case 0xe9:      /* near relative jump */
213         case 0xeb:      /* short relative jump */
214                 break;
215         case 0x0f:
216                 if ((insn->opcode.bytes[1] & 0xf0) == 0x80) /* jcc near */
217                         break;
218                 return 0;
219         default:
220                 if ((insn->opcode.bytes[0] & 0xf0) == 0x70) /* jcc short */
221                         break;
222                 return 0;
223         }
            /* 
             * 在can_optimize中将next_byte设置为下一条指令的起始地址，这样
             * 当next_byte + immediate.value之后就会得到跳转的地址，因为间接跳转
             * 是相对于下一条指令的地址的，即相对于执行时EIP的内容
             */
224         target = (unsigned long)insn->next_byte + insn->immediate.value;
225 
226         return (start <= target && target <= start + len);
227 }


 26 struct insn_field {
 27         union {
 28                 insn_value_t value;
 29                 insn_byte_t bytes[4];
 30         };
 31         /* !0 if we've run insn_get_xxx() for this field */
 32         unsigned char got;
 33         unsigned char nbytes;
 34 };
 35 
 36 struct insn {
 37         struct insn_field prefixes;     /*
 38                                          * Prefixes
 39                                          * prefixes.bytes[3]: last prefix
 40                                          */
 41         struct insn_field rex_prefix;   /* REX prefix */
 42         struct insn_field vex_prefix;   /* VEX prefix */
 43         struct insn_field opcode;       /*
 44                                          * opcode.bytes[0]: opcode1
 45                                          * opcode.bytes[1]: opcode2
 46                                          * opcode.bytes[2]: opcode3
 47                                          */
 48         struct insn_field modrm;
 49         struct insn_field sib;
 50         struct insn_field displacement;
 51         union {
 52                 struct insn_field immediate;
 53                 struct insn_field moffset1;     /* for 64bit MOV */
 54                 struct insn_field immediate1;   /* for 64bit imm or off16/32 */
 55         };
 56         union {
 57                 struct insn_field moffset2;     /* for 64bit MOV */
 58                 struct insn_field immediate2;   /* for 64bit imm or seg16 */
 59         };
 60 
 61         insn_attr_t attr;
 62         unsigned char opnd_bytes;
 63         unsigned char addr_bytes;
 64         unsigned char length;
 65         unsigned char x86_64;
 66 
 67         const insn_byte_t *kaddr;       /* kernel address of insn to analyze */
 68         const insn_byte_t *next_byte;
 69 };
 70 
 71 #define MAX_INSN_SIZE   16
 72 

/*********************************************************************************************************
 ********************************************** 注册 jprobe **********************************************
 *********************************************************************************************************
 */
      /* jps: jprobe数组; num：jps中元素个数 */
1699  int __kprobes register_jprobes(struct jprobe **jps, int num)
1700  {
1701    struct jprobe *jp;
1702    int ret = 0, i;
1703
1704    if (num <= 0)
1705      return -EINVAL;
1706    for (i = 0; i < num; i++) {
1707      unsigned long addr, offset;
1708      jp = jps[i];
          /* 
           * 获取探测点地址 在X86上仅仅将jp->entry转换为unsigned long类型
           * jp->entry为用户自己实现的一个代理函数，该地址位于用户编写的模
           * 块中。
           */
1709       addr = arch_deref_entry_point(jp->entry);
1710
1711      /* Verify probepoint is a function entry point */
          /*
           *  offset == 0是为了保证addr为一个函数的首地址
           */
1712       if (kallsyms_lookup_size_offset(addr, NULL, &offset) &&
1713          offset == 0) {
              /*
               * pre_handler用于第一次INT3异常后调用，表示在运行探测点指
               * 之前执行的函数，setjmp_pre_handler它负责保存寄存器集合
               * 和栈上的数据。
               * break_handler用于处理jprobe_return()产生的INT3异常，
               * longjmp_break_handler恢复寄存器集合和栈上的数据
               */
1714				jp->kp.pre_handler = setjmp_pre_handler;
1715				jp->kp.break_handler = longjmp_break_handler;
            /*jprobe是基于kprobe的，注册对应的kprobe*/
1716				ret = register_kprobe(&jp->kp);
1717			} else
1718				  ret = -EINVAL;
1719	
1720			if (ret < 0) {
1721				if (i > 0)
1722					unregister_jprobes(jps, i);
1723				break;
1724			}
1725		}
1726		return ret;
1727	}
1728	EXPORT_SYMBOL_GPL(register_jprobes);
1729	
1730	int __kprobes register_jprobe(struct jprobe *jp)
1731	{
1732		return register_jprobes(&jp, 1);
1733	}
1734	EXPORT_SYMBOL_GPL(register_jprobe);

     /*
      *  jprobe中设置的pre_handler
      *  p : jprobe结构中的kprobe指针
      *  regs: 当前执行环境的寄存器集合
      */
1007 int __kprobes setjmp_pre_handler(struct kprobe *p, struct pt_regs *regs)
1008 {
1009         struct jprobe *jp = container_of(p, struct jprobe, kp);
1010         unsigned long addr;
1011         struct kprobe_ctlblk *kcb = get_kprobe_ctlblk();
1012         /* 保存当前的寄存器 */
1013         kcb->jprobe_saved_regs = *regs;
1014         kcb->jprobe_saved_sp = stack_addr(regs);
1015         addr = (unsigned long)(kcb->jprobe_saved_sp);
1016 
1017         /*
1018          * As Linus pointed out, gcc assumes that the callee
1019          * owns the argument space and could overwrite it, e.g.
1020          * tailcall optimization. So, to be absolutely safe
1021          * we also save and restore enough stack bytes to cover
1022          * the argument area.
1023          */
             /* 保存当前的栈空间 */
1024         memcpy(kcb->jprobes_stack, (kprobe_opcode_t *)addr,
1025                MIN_STACK_SIZE(addr));
             /* 清除EFLAGS_IF，CPU不可相应外部中断 */
1026         regs->flags &= ~X86_EFLAGS_IF;
             /* 跟踪硬件中断关闭，主要用于调试 */
1027         trace_hardirqs_off();
             /* 将ip设置为用户注册的处理函数 */
1028         regs->ip = (unsigned long)(jp->entry);
1029         return 1;
1030 }

1049 int __kprobes longjmp_break_handler(struct kprobe *p, struct pt_regs *regs)
1050 {
1051         struct kprobe_ctlblk *kcb = get_kprobe_ctlblk();
             /*
              * 得出jprobe_return()中 INT 3指令的地址，INT 3指令只占一个字节,
              * 因此减一
              */
1052         u8 *addr = (u8 *) (regs->ip - 1);
1053         struct jprobe *jp = container_of(p, struct jprobe, kp);
1054         /*
              * 检查addr是否在jprobe_return函数地址范围内，jprobe_return_end定义
              * 在jprobe_return函数中   
              */
1055         if ((addr > (u8 *) jprobe_return) &&
1056             (addr < (u8 *) jprobe_return_end)) {
                     /* 若当前的寄存器集合与保存的不一样，则说明有BUG*/
1057                 if (stack_addr(regs) != kcb->jprobe_saved_sp) {
1058                         struct pt_regs *saved_regs = &kcb->jprobe_saved_regs;
1059                         printk(KERN_ERR
1060                                "current sp %p does not match saved sp %p\n",
1061                                stack_addr(regs), kcb->jprobe_saved_sp);
1062                         printk(KERN_ERR "Saved registers for jprobe %p\n", jp);
1063                         show_regs(saved_regs);
1064                         printk(KERN_ERR "Current registers\n");
1065                         show_regs(regs);
1066                         BUG();
1067                 }
                     /* 恢复寄存器集合和栈中的数据 */
1068                 *regs = kcb->jprobe_saved_regs;
1069                 memcpy((kprobe_opcode_t *)(kcb->jprobe_saved_sp),
1070                        kcb->jprobes_stack,
1071                        MIN_STACK_SIZE(kcb->jprobe_saved_sp));
                     /* 激活内核抢占但不检查任何需要调度的任务 */
1072                 preempt_enable_no_resched();
1073                 return 1;
1074         }
1075         return 0;
1076 }


1032 void __kprobes jprobe_return(void)
1033 {
1034         struct kprobe_ctlblk *kcb = get_kprobe_ctlblk();
1035 
1036         asm volatile (
1037 #ifdef CONFIG_X86_64
1038                         "       xchg   %%rbx,%%rsp      \n"
1039 #else
1040                         "       xchgl   %%ebx,%%esp     \n"
1041 #endif
1042                         "       int3                    \n"
1043                         "       .globl jprobe_return_end\n"
1044                         "       jprobe_return_end:      \n"
1045                         "       nop                     \n"::"b"
1046                         (kcb->jprobe_saved_sp):"memory");
1047 }
1048 


510 /*
511  * We have reentered the kprobe_handler(), since another probe was hit while
512  * within the handler. We save the original kprobes variables and just single
513  * step on the instruction of the new probe without calling any user handlers.
514  */
515 static int __kprobes
516 reenter_kprobe(struct kprobe *p, struct pt_regs *regs, struct kprobe_ctlblk *kcb)
517 {
518         switch (kcb->kprobe_status) {
            /* KPROBE_HIT_SSDONE：在post_kprobe_handler中设置，表示单步调试结束*/
519         case KPROBE_HIT_SSDONE:
            /*  
             *  KPROBE_HIT_ACTIVE：在kprobe_handler中设置，表示单步调试开始，还没
             *  结束。
             */
520         case KPROBE_HIT_ACTIVE:
521                 kprobes_inc_nmissed_count(p);
522                 setup_singlestep(p, regs, kcb, 1);
523                 break;
524         case KPROBE_HIT_SS:
525                 /* A probe has been hit in the codepath leading up to, or just
526                  * after, single-stepping of a probed instruction. This entire
527                  * codepath should strictly reside in .kprobes.text section.
528                  * Raise a BUG or we'll continue in an endless reentering loop
529                  * and eventually a stack overflow.
530                  */
531                 printk(KERN_WARNING "Unrecoverable kprobe detected at %p.\n",
532                        p->addr);
533                 dump_kprobe(p);
534                 BUG();
535         default:
536                 /* impossible cases */
537                 WARN_ON(1);
538                 return 0;
539         }
540 
541         return 1;
542 }

/* per-cpu kprobe control block */
/*
 *  kprobe_old_flags：为执行被保存的指令之前的flags
 *  kprobe_saved_flags:为执行被保存的指令之后的flags
 *  因为被保存的指令可能会修改中断设置，所以要分开存放flags，这个
 *  flags只保存TF和IF设置
 */
105 struct kprobe_ctlblk {
106         unsigned long kprobe_status;
107         unsigned long kprobe_old_flags;
108         unsigned long kprobe_saved_flags;
109         unsigned long *jprobe_saved_sp;
110         struct pt_regs jprobe_saved_regs;
111         kprobe_opcode_t jprobes_stack[MAX_STACK_SIZE];
112         struct prev_kprobe prev_kprobe;
113 };
 96 
 97 struct prev_kprobe {
 98         struct kprobe *kp;
 99         unsigned long status;
100         unsigned long old_flags;
101         unsigned long saved_flags;
102 };
/* 将当前CPU上的current_kprobe保存到kcb中的prev_kprobe中*/
415 static void __kprobes save_previous_kprobe(struct kprobe_ctlblk *kcb)
416 {
417         kcb->prev_kprobe.kp = kprobe_running();
418         kcb->prev_kprobe.status = kcb->kprobe_status;
419         kcb->prev_kprobe.old_flags = kcb->kprobe_old_flags;
420         kcb->prev_kprobe.saved_flags = kcb->kprobe_saved_flags;
421 }

static void __kprobes set_current_kprobe(struct kprobe *p, struct pt_regs *regs,
432            struct kprobe_ctlblk *kcb)
433 {
      /* 设置current_kprobe为新的kprobe，这个kprobe就是第二次进入的kprobe */
434   __this_cpu_write(current_kprobe, p);
435   kcb->kprobe_saved_flags = kcb->kprobe_old_flags
436   = (regs->flags & (X86_EFLAGS_TF | X86_EFLAGS_IF));
      /* 如果被保存的指令会修改IF标志，IF标志表示开关CPU中断，
       * kprobe_saved_flags清除X86_EFLAGS_IF 
       */
437   if (is_IF_modifier(p->ainsn.insn))
438     kcb->kprobe_saved_flags &= ~X86_EFLAGS_IF;
439 }


/*****************************************************************************
 ******************************   kretprobe **********************************
 *****************************************************************************/
188 /*
189  * Function-return probe -
190  * Note:
191  * User needs to provide a handler function, and initialize maxactive.
192  * maxactive - The maximum number of instances of the probed function that
193  * can be active concurrently.
194  * nmissed - tracks the number of times the probed function's return was
195  * ignored, due to maxactive being too low.
196  *
197  */
198 struct kretprobe {
199         struct kprobe kp;
200         kretprobe_handler_t handler;
201         kretprobe_handler_t entry_handler;
202         int maxactive;
203         int nmissed;
204         size_t data_size;
            /* free_instances:用于链接未使用的返回地址实例，在注册时初始化*/
205         struct hlist_head free_instances;
206         raw_spinlock_t lock;
207 };
208 
209 struct kretprobe_instance {
            /* hlist用于链接多个instance */
210         struct hlist_node hlist;
211         struct kretprobe *rp;
212         kprobe_opcode_t *ret_addr;
213         struct task_struct *task;
214         char data[0];
215 };
1807 int __kprobes register_kretprobe(struct kretprobe *rp)
1808 {
1809         int ret = 0;
1810         struct kretprobe_instance *inst;
1811         int i;
1812         void *addr;
1813         /* 检查注册的探测点是否在黑名单上，若是，则返回错误*/ 
1814         if (kretprobe_blacklist_size) {
1815                 addr = kprobe_addr(&rp->kp);
1816                 if (IS_ERR(addr))
1817                         return PTR_ERR(addr);
1818 
1819                 for (i = 0; kretprobe_blacklist[i].name != NULL; i++) {
1820                         if (kretprobe_blacklist[i].addr == addr)
1821                                 return -EINVAL;
1822                 }
1823         }
1824 
1825         rp->kp.pre_handler = pre_handler_kretprobe;
1826         rp->kp.post_handler = NULL;
1827         rp->kp.fault_handler = NULL;
1828         rp->kp.break_handler = NULL;
1829 
1830         /* Pre-allocate memory for max kretprobe instances */
1831         if (rp->maxactive <= 0) {
1832 #ifdef CONFIG_PREEMPT
1833                 rp->maxactive = max_t(unsigned int, 10, 2*num_possible_cpus());
1834 #else
1835                 rp->maxactive = num_possible_cpus();
1836 #endif
1837         }
1838         raw_spin_lock_init(&rp->lock);
1839         INIT_HLIST_HEAD(&rp->free_instances);
1840         for (i = 0; i < rp->maxactive; i++) {
1841                 inst = kmalloc(sizeof(struct kretprobe_instance) +
1842                                rp->data_size, GFP_KERNEL);
1843                 if (inst == NULL) {
1844                         free_rp_inst(rp);
1845                         return -ENOMEM;
1846                 }
1847                 INIT_HLIST_NODE(&inst->hlist);
                     /* 将新建的instance加入到free_instances中 */
1848                 hlist_add_head(&inst->hlist, &rp->free_instances);
1849         }
1850 
1851         rp->nmissed = 0;
1852         /* Establish function entry probe point */
1853         ret = register_kprobe(&rp->kp);
1854         if (ret != 0)
1855                 free_rp_inst(rp);
1856         return ret;
1857 }
1858 EXPORT_SYMBOL_GPL(register_kretprobe);

1762 #ifdef CONFIG_KRETPROBES
1763 /*
1764  * This kprobe pre_handler is registered with every kretprobe. When probe
1765  * hits it will set up the return probe.
1766  */
1767 static int __kprobes pre_handler_kretprobe(struct kprobe *p,
1768                                            struct pt_regs *regs)
1769 {
1770         struct kretprobe *rp = container_of(p, struct kretprobe, kp);
1771         unsigned long hash, flags = 0;
1772         struct kretprobe_instance *ri;
1773 
1774         /*TODO: consider to only swap the RA after the last pre_handler fired */
1775         hash = hash_ptr(current, KPROBE_HASH_BITS);
1776         raw_spin_lock_irqsave(&rp->lock, flags);
1777         if (!hlist_empty(&rp->free_instances)) {
                     /* 
                      * 若free_instances不为空,则遍历每一个free_instances中的
                      * kretprobe_instance
                      */
1778                 ri = hlist_entry(rp->free_instances.first,
1779                                 struct kretprobe_instance, hlist);
                     /* 将遍历的kretprobe_instance从free_instances中删除 */
1780                 hlist_del(&ri->hlist);
1781                 raw_spin_unlock_irqrestore(&rp->lock, flags);
1782 
1783                 ri->rp = rp;
1784                 ri->task = current;
1785                 /* 
                      * 若用户注册的entry_handler不为空，则执行，若返回非零，
                      * 则不再继续处理
                      */
1786                 if (rp->entry_handler && rp->entry_handler(ri, regs)) {
1787                         raw_spin_lock_irqsave(&rp->lock, flags);
1788                         hlist_add_head(&ri->hlist, &rp->free_instances);
1789                         raw_spin_unlock_irqrestore(&rp->lock, flags);
1790                         return 0;
1791                 }
1792 
1793                 arch_prepare_kretprobe(ri, regs);
1794 
1795                 /* XXX(hch): why is there no hlist_move_head? */
                     /* 将kretprobe_instance加入到kretprobe_inst_table中*/
1796                 INIT_HLIST_NODE(&ri->hlist);
1797                 kretprobe_table_lock(hash, &flags);
1798                 hlist_add_head(&ri->hlist, &kretprobe_inst_table[hash]);
1799                 kretprobe_table_unlock(hash, &flags);
1800         } else {
                    /* 若没有空闲的kretprobe_instance，则增加kretprobe的nmissed*/
1801                 rp->nmissed++;
1802                 raw_spin_unlock_irqrestore(&rp->lock, flags);
1803         }
1804         return 0;
1805 }

461 void __kprobes
462 arch_prepare_kretprobe(struct kretprobe_instance *ri, struct pt_regs *regs)
463 {
464         unsigned long *sara = stack_addr(regs);
465         /* 将探测点真正的地址保存在ret_addr中 */
466         ri->ret_addr = (kprobe_opcode_t *) *sara;
467 
468         /* Replace the return addr with trampoline addr */
            /* 当函数返回时，将执行kretprobe_trampoline */
469         *sara = (unsigned long) &kretprobe_trampoline;
470 }

634 /*
635  * When a retprobed function returns, this code saves registers and
636  * calls trampoline_handler() runs, which calls the kretprobe's handler.
637  */
638 static void __used __kprobes kretprobe_trampoline_holder(void)
639 {
640         asm volatile (
641                         ".global kretprobe_trampoline\n"
642                         "kretprobe_trampoline: \n"
643 #ifdef CONFIG_X86_64
644                         /* We don't bother saving the ss register */
645                         "       pushq %rsp\n"
646                         "       pushfq\n"
647                         SAVE_REGS_STRING
648                         "       movq %rsp, %rdi\n"
649                         "       call trampoline_handler\n"
650                         /* Replace saved sp with true return address. */
651                         "       movq %rax, 152(%rsp)\n"
652                         RESTORE_REGS_STRING
653                         "       popfq\n"
654 #else
655                         "       pushf\n"  /* pushf将EFLAGS的低16位压入堆栈*/
656                         SAVE_REGS_STRING
657                         "       movl %esp, %eax\n"
658                         "       call trampoline_handler\n"
659                         /* Move flags to cs */
660                         "       movl 56(%esp), %edx\n"
661                         "       movl %edx, 52(%esp)\n"
662                         /* Replace saved flags with true return address. */
663                         "       movl %eax, 56(%esp)\n"
664                         RESTORE_REGS_STRING
665                         "       popf\n"
666 #endif
667                         "       ret\n");
668 }


670 /*
671  * Called from kretprobe_trampoline
672  */
673 static __used __kprobes void *trampoline_handler(struct pt_regs *regs)
674 {
675         struct kretprobe_instance *ri = NULL;
676         struct hlist_head *head, empty_rp;
677         struct hlist_node *node, *tmp;
678         unsigned long flags, orig_ret_address = 0;
679         unsigned long trampoline_address = (unsigned long)&kretprobe_trampoline;
680         kprobe_opcode_t *correct_ret_addr = NULL;
681 
682         INIT_HLIST_HEAD(&empty_rp);
683         kretprobe_hash_lock(current, &head, &flags);
684         /* fixup registers */
685 #ifdef CONFIG_X86_64
686         regs->cs = __KERNEL_CS;
687 #else
688         regs->cs = __KERNEL_CS | get_kernel_rpl();
689         regs->gs = 0;
690 #endif
691         regs->ip = trampoline_address;
692         regs->orig_ax = ~0UL;
693 
694         /*
695          * It is possible to have multiple instances associated with a given
696          * task either because multiple functions in the call path have
697          * return probes installed on them, and/or more than one
698          * return probe was registered for a target function.
699          *
700          * We can handle this because:
701          *     - instances are always pushed into the head of the list
702          *     - when multiple return probes are registered for the same
703          *       function, the (chronologically) first instance's ret_addr
704          *       will be the real return address, and all the rest will
705          *       point to kretprobe_trampoline.
706          */
             /*
              *  从整个的instance链表中找出真正的返回地址
              */
707         hlist_for_each_entry_safe(ri, node, tmp, head, hlist) {
708                 if (ri->task != current)
709                         /* another task is sharing our hash bucket */
710                         continue;
711 
712                 orig_ret_address = (unsigned long)ri->ret_addr;
713 
714                 if (orig_ret_address != trampoline_address)
715                         /*
716                          * This is the real return address. Any other
717                          * instances associated with this task are for
718                          * other calls deeper on the call stack
719                          */
720                         break;
721         }
722 
723         kretprobe_assert(ri, orig_ret_address, trampoline_address);
724 
725         correct_ret_addr = ri->ret_addr;
            /* 
             * 以下循环依次执行用户注册的调试函数，然后修改返回地址为
             * 真正的返回地址 
             */
726         hlist_for_each_entry_safe(ri, node, tmp, head, hlist) {
727                 if (ri->task != current)
728                         /* another task is sharing our hash bucket */
729                         continue;
730 
731                 orig_ret_address = (unsigned long)ri->ret_addr;
732                 if (ri->rp && ri->rp->handler) {
733                         __this_cpu_write(current_kprobe, &ri->rp->kp);
                            /* 设置krpobe_status为KPROBE_HIT_ACTIVE表明探测点命中 */
734                         get_kprobe_ctlblk()->kprobe_status = KPROBE_HIT_ACTIVE;
735                         ri->ret_addr = correct_ret_addr;
736                         ri->rp->handler(ri, regs);
737                         __this_cpu_write(current_kprobe, NULL);
738                 }
739                 /*
                     *  recycle_rp_inst：若ketprobe_instance包含的kretprobe为不为空，
                     *  将已经使用过的kretprobe_instance重新装入到free_instances 
                     *  链表中；否则，将该instance链入到empty_rp链表中
                     */
740                 recycle_rp_inst(ri, &empty_rp);
741                 /* 
                     * 探测点相同的多个instance组成的链表中，第一个instance的ret_addr
                     * 保存了真正的返回地址，其他的ret_addr为trampoline_address
                     */
742                 if (orig_ret_address != trampoline_address)
743                         /*
744                          * This is the real return address. Any other
745                          * instances associated with this task are for
746                          * other calls deeper on the call stack
747                          */
748                         break;
749         }
750 
751         kretprobe_hash_unlock(current, &flags);
752         /* 将empty_rp中的instance释放掉 */ 
753         hlist_for_each_entry_safe(ri, node, tmp, &empty_rp, hlist) {
754                 hlist_del(&ri->hlist);
755                 kfree(ri);
756         }
757         return (void *)orig_ret_address;
758 }

