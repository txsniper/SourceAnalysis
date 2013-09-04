/********************************************************************************************************
 ******************************************  注册 kprobe ************************************************
 ********************************************************************************************************
 */
/*
 *
 *
 *
1.4 How Does Jump Optimization Work?
167	
168   If your kernel is built with CONFIG_OPTPROBES=y (currently this flag
169	is automatically set 'y' on x86/x86-64, non-preemptive kernel) and
170	the "debug.kprobes_optimization" kernel parameter is set to 1 (see
171	sysctl(8)), Kprobes tries to reduce probe-hit overhead by using a jump
172	instruction instead of a breakpoint instruction at each probepoint.
173	
174	1.4.1 Init a Kprobe
175	
176	When a probe is registered, before attempting this optimization,
177	Kprobes inserts an ordinary, breakpoint-based kprobe at the specified
178	address. So, even if it's not possible to optimize this particular
179	probepoint, there'll be a probe there.
180	
181	1.4.2 Safety Check
182	
183	Before optimizing a probe, Kprobes performs the following safety checks:
184	
185	- Kprobes verifies that the region that will be replaced by the jump
186	instruction (the "optimized region") lies entirely within one function.
187	(A jump instruction is multiple bytes, and so may overlay multiple
188	instructions.)
189	
190	- Kprobes analyzes the entire function and verifies that there is no
191	   jump into the optimized region.  Specifically:
192	  - the function contains no indirect jump;
193	  - the function contains no instruction that causes an exception (since
194	  the fixup code triggered by the exception could jump back into the
195	  optimized region -- Kprobes checks the exception tables to verify this);
196	  and
197	  - there is no near jump to the optimized region (other than to the first
198	  byte).
200	  - For each instruction in the optimized region, Kprobes verifies that
201	    the instruction can be executed out of line.
202	
203	1.4.3 Preparing Detour Buffer
204	
205	Next, Kprobes prepares a "detour" buffer, which contains the following
206	instruction sequence:
207	- code to push the CPU's registers (emulating a breakpoint trap)
208	- a call to the trampoline code which calls user's probe handlers.
209	- code to restore registers
210	- the instructions from the optimized region
211	- a jump back to the original execution path.
212	
213	1.4.4 Pre-optimization
214	
215    After preparing the detour buffer, Kprobes verifies that none of the
216	following situations exist:
217	- The probe has either a break_handler (i.e., it's a jprobe) or a
218	post_handler.
219	- Other instructions in the optimized region are probed.
220	- The probe is disabled.
221	In any of the above cases, Kprobes won't start optimizing the probe.
222	Since these are temporary situations, Kprobes tries to start
223	optimizing it again if the situation is changed.
224	
225	If the kprobe can be optimized, Kprobes enqueues the kprobe to an
226	optimizing list, and kicks the kprobe-optimizer workqueue to optimize
227	it.  If the to-be-optimized probepoint is hit before being optimized,
228	Kprobes returns control to the original instruction path by setting
229	the CPU's instruction pointer to the copied code in the detour buffer
230	-- thus at least avoiding the single-step.
231	
232	1.4.5 Optimization
233	
234	   The Kprobe-optimizer doesn't insert the jump instruction immediately;
235	rather, it calls synchronize_sched() for safety first, because it's
236	possible for a CPU to be interrupted in the middle of executing the
237	optimized region(*).  As you know, synchronize_sched() can ensure
238	that all interruptions that were active when synchronize_sched()
239	was called are done, but only if CONFIG_PREEMPT=n.  So, this version
240	of kprobe optimization supports only kernels with CONFIG_PREEMPT=n.(**)
241	
242	   After that, the Kprobe-optimizer calls stop_machine() to replace
243	the optimized region with a jump instruction to the detour buffer,
244	using text_poke_smp().
245	
246	1.4.6 Unoptimization
247	
248   When an optimized kprobe is unregistered, disabled, or blocked by
249	another kprobe, it will be unoptimized.  If this happens before
250	the optimization is complete, the kprobe is just dequeued from the
251	optimized list.  If the optimization has been done, the jump is
252	replaced with the original code (except for an int3 breakpoint in
253	the first byte) by using text_poke_smp().
254	
255	(*)Please imagine that the 2nd instruction is interrupted and then
256	the optimizer replaces the 2nd instruction with the jump *address*
257	while the interrupt handler is running. When the interrupt
258	returns to original address, there is no valid instruction,
259	and it causes an unexpected result.
260	
261	(**)This optimization-safety checking may be replaced with the
262	stop-machine method that ksplice uses for supporting a CONFIG_PREEMPT=y
263	kernel.
264	
265	NOTE for geeks:
266	     The jump optimization changes the kprobe's pre_handler behavior.
267	Without optimization, the pre_handler can change the kernel's execution
268	path by changing regs->ip and returning 1.  However, when the probe
269	is optimized, that modification is ignored.  Thus, if you want to
270	tweak the kernel's execution path, you need to suppress optimization,
271	using one of the following techniques:
272	- Specify an empty function for the kprobe's post_handler or break_handler.
273	 or
274	- Execute 'sysctl -w debug.kprobes_optimization=n'
275	
276	2. Architectures Supported
277	
278	Kprobes, jprobes, and return probes are implemented on the following
279	architectures:
280	
281	- i386 (Supports jump optimization)
282	- x86_64 (AMD-64, EM64T) (Supports jump optimization)
283	- ppc64
284	- ia64 (Does not support probes on instruction slot1.)
285	- sparc64 (Return probes not yet implemented.)
286	- arm
287	- ppc
288	- mips
 * 
 *
      On x86/x86-64, since the Jump Optimization of Kprobes modifies
575	instructions widely, there are some limitations to optimization. To
576	explain it, we introduce some terminology. Imagine a 3-instruction
577	sequence consisting of a two 2-byte instructions and one 3-byte
578	instruction.
579	
580	        IA
581	         |
582	[-2][-1][0][1][2][3][4][5][6][7]
583	        [ins1][ins2][  ins3 ]
584	        [<-     DCR       ->]
585	           [<- JTPR ->]
586	
587	ins1: 1st Instruction
588	ins2: 2nd Instruction
589	ins3: 3rd Instruction
590	IA:  Insertion Address
591	JTPR: Jump Target Prohibition Region
592	DCR: Detoured Code Region
593	
594	The instructions in DCR are copied to the out-of-line buffer
595	of the kprobe, because the bytes in DCR are replaced by
596	a 5-byte jump instruction. So there are several limitations.
597	
598	a) The instructions in DCR must be relocatable.
599	b) The instructions in DCR must not include a call instruction.
600	c) JTPR must not be targeted by any jump or call instruction.
601	d) DCR must not straddle the border between functions.
602	
603	Anyway, these limitations are checked by the in-kernel instruction
604	decoder, so you don't need to worry about that.
 * 
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

149 /**
150  * __get_insn_slot() - Find a slot on an executable page for an instruction.
151  * We allocate an executable page if there's no room on existing ones.
152  */
153 static kprobe_opcode_t __kprobes *__get_insn_slot(struct kprobe_insn_cache *c)
154 {
155         struct kprobe_insn_page *kip;
156 
157  retry:
158         list_for_each_entry(kip, &c->pages, list) {
159                 if (kip->nused < slots_per_page(c)) {
160                         int i;
161                         for (i = 0; i < slots_per_page(c); i++) {
162                                 if (kip->slot_used[i] == SLOT_CLEAN) {
163                                         kip->slot_used[i] = SLOT_USED;
164                                         kip->nused++;
165                                         return kip->insns + (i * c->insn_size);
166                                 }
167                         }
168                         /* kip->nused is broken. Fix it. */
169                         kip->nused = slots_per_page(c);
170                         WARN_ON(1);
171                 }
172         }
173 
174         /* If there are any garbage slots, collect it and try again. */
175         if (c->nr_garbage && collect_garbage_slots(c) == 0)
176                 goto retry;
177 
178         /* All out of space.  Need to allocate a new page. */
179         kip = kmalloc(KPROBE_INSN_PAGE_SIZE(slots_per_page(c)), GFP_KERNEL);
180         if (!kip)
181                 return NULL;
182 
183         /*
184          * Use module_alloc so this page is within +/- 2GB of where the
185          * kernel image and loaded module images reside. This is required
186          * so x86_64 can correctly handle the %rip-relative fixups.
187          */
188         kip->insns = module_alloc(PAGE_SIZE);
189         if (!kip->insns) {
190                 kfree(kip);
191                 return NULL;
192         }
193         INIT_LIST_HEAD(&kip->list);
194         memset(kip->slot_used, SLOT_CLEAN, slots_per_page(c));
195         kip->slot_used[0] = SLOT_USED;
196         kip->nused = 1;
197         kip->ngarbage = 0;
198         list_add(&kip->list, &c->pages);
199         return kip->insns;
200 }
201 
202 
203 kprobe_opcode_t __kprobes *get_insn_slot(void)
204 {
205         kprobe_opcode_t *ret = NULL;
206 
207         mutex_lock(&kprobe_insn_mutex);
208         ret = __get_insn_slot(&kprobe_insn_slots);
209         mutex_unlock(&kprobe_insn_mutex);
210 
211         return ret;
212 }
213 
 
