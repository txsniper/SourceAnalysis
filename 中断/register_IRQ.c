/*
 * 一.数据结构：
 *   struct irq_desc irq_desc[NR_IRQS];  每个数组项对应一个IRQ
 *   struct irq_chip;   描述了一个IRQ控制器抽象
 *   struct irqaction;  描述中断处理函数，共享一个IRQ编号的处理函数构成一个链表
 *  
 *
 * 二. 注册IRQ:
 *  static inline int __must_check
           request_irq(unsigned int irq, irq_handler_t handler, unsigned long flags,
                       const char *name, void *dev)
    {
         return request_threaded_irq(irq, handler, NULL, flags, name, dev);
    } 
       在request_irq函数中，又调用request_threaded_irq
 *     request_threaded_irq - allocate an interrupt line
 *      @irq: Interrupt line to allocate（需要分配的IRQ编号）
 *      @handler: Function to be called when the IRQ occurs.
 *                Primary handler for threaded interrupts
 *                If NULL and thread_fn != NULL the default
 *                primary handler is installed
 *                （中断请求发生时调用的处理函数，若启用了中断
 *                线程化，则中断发生时，处理中断的线程将调用这
 *                个函数来处理中断请求）
 *      @thread_fn: Function called from the irq handler thread
 *                  If NULL, no irq thread is created
 *                 （处理中断的线程调用的函数，如果为NULL，则
 *                 不会创建处理中断的线程，即没有启用中断线程化）
 *      @irqflags: Interrupt type flags
 *                 （表示中断标志位）
 *      @devname: An ascii name for the claiming device
 *               （表示请求中断的设备的名称）
 *      @dev_id: A cookie passed back to the handler function
 *               （对应于request_irq()函数中所传递的第五个参数，
 *               可取任意值，但必须唯一能够代表发出中断请求的设备，
 *               通常取描述该设备的结构体。 共享中断时这个参数不能
 *               为空。） 
 */

1394 int request_threaded_irq(unsigned int irq, irq_handler_t handler,
1395                          irq_handler_t thread_fn, unsigned long irqflags,
1396                          const char *devname, void *dev_id)
1397 {
1398         struct irqaction *action;
1399         struct irq_desc *desc;
1400         int retval;
1401 
1402         /*
1403          * Sanity-check: shared interrupts must pass in a real dev-ID,
1404          * otherwise we'll have trouble later trying to figure out
1405          * which interrupt is which (messes up the interrupt freeing
1406          * logic etc).
1407          */
              /*若注册的为共享中断，则dev_id不能为空，否则出错返回*/
1408         if ((irqflags & IRQF_SHARED) && !dev_id)
1409                 return -EINVAL;
1410         /*通过irq编号返回irq_desc[NR_IRQS]数组中的一个具体的irq_desc*/
1411         desc = irq_to_desc(irq);
1412         if (!desc)
1413                 return -EINVAL;
1414         /* 
             *  判断得到的desc能否被请求，若desc->status_use_accessors中的
             *  _IRQ_NOREQUEST置位，则表明无法通过request_irq函数注册
             */
1415         if (!irq_settings_can_request(desc) ||
1416             WARN_ON(irq_settings_is_per_cpu_devid(desc)))
1417                 return -EINVAL;
1418         /*
              * 若handler为NULL并且thread_fn为NULL，则出错返回
              * 若handler为NULL但thread_fn不为NULL，则handler
              * 被设置为irq_default_primary_handler，这个函数仅
              * 仅返回IRQ_WAKE_THREAD，这将对启用中断线程化  
              */
1419         if (!handler) {
1420                 if (!thread_fn)
1421                         return -EINVAL;
1422                 handler = irq_default_primary_handler;
1423         }

1424         /* 分配描述中断处理函数的结构，并初始化其中的成员 */
1425         action = kzalloc(sizeof(struct irqaction), GFP_KERNEL);
1426         if (!action)
1427                 return -ENOMEM;
1428 
1429         action->handler = handler;
1430         action->thread_fn = thread_fn;
1431         action->flags = irqflags;
1432         action->name = devname;
1433         action->dev_id = dev_id;
1434         /* 如果中断控制器挂在慢速总线上，则现在锁住总线*/
1435         chip_bus_lock(desc);
             /*__setup_irq用于注册中断处理程序，若出错返回非0*/
1436         retval = __setup_irq(irq, desc, action);
             /* 解锁 */
1437         chip_bus_sync_unlock(desc);
1438 
1439         if (retval)
1440                 kfree(action);
1441 
     /*
      *  CONFIG_DEBUG_SHIRQ_FIXME标志与调试共享中断相关，若
      *  中断是共享中断，则首先屏蔽中断并保存中断状态，执行
      *  注册的中断处理函数后恢复      
      */
1442 #ifdef CONFIG_DEBUG_SHIRQ_FIXME
1443         if (!retval && (irqflags & IRQF_SHARED)) {
1444                 /*
1445                  * It's a shared IRQ -- the driver ought to be prepared for it
1446                  * to happen immediately, so let's make sure....
1447                  * We disable the irq to make sure that a 'real' IRQ doesn't
1448                  * run in parallel with our fake.
1449                  */
1450                 unsigned long flags;
1451 
1452                 disable_irq(irq);
1453                 local_irq_save(flags);
1454 
1455                 handler(irq, dev_id);
1456 
1457                 local_irq_restore(flags);
1458                 enable_irq(irq);
1459         }
1460 #endif
1461         return retval;
1462 }
1463 EXPORT_SYMBOL(request_threaded_irq);
1464 

/*
 * 注册中断的真正工作交给了 __setup_irq，下面来分析它
 *
 */

904 /*
905  * Internal function to register an irqaction - typically used to
906  * allocate special interrupts that are part of the architecture.
907  */
908 static int
909 __setup_irq(unsigned int irq, struct irq_desc *desc, struct irqaction *new)
910 {
911         struct irqaction *old, **old_ptr;
912         unsigned long flags, thread_mask = 0;
913         int ret, nested, shared = 0;
914         cpumask_var_t mask;
915 
916         if (!desc)
917                 return -EINVAL;
918         /* 没有中断控制器，返回-ENOSYS*/
919         if (desc->irq_data.chip == &no_irq_chip)
920                 return -ENOSYS;
            /* 尝试增加设备模块的引用计数，若设备没栽入内核，返回-ENODEV*/
921         if (!try_module_get(desc->owner))
922                 return -ENODEV;
923 
924         /*
925          * Check whether the interrupt nests into another interrupt
926          * thread.
927          */
            /*
             *  检查是否嵌套在另一个中断线程中，若是则总是出错？？？
             *  不能在中断线程中注册中断？？？
             */
928         nested = irq_settings_is_nested_thread(desc);
929         if (nested) {
                    /* 
                     * 嵌套在另一个中断线程中，并且要注册的是一个不支持
                     * 线程化中断的irq，则返回-EINVAL（表示参数出错）
                     */
930                 if (!new->thread_fn) {
931                         ret = -EINVAL;
932                         goto out_mput;
933                 }
934                 /*
935                  * Replace the primary handler which was provided from
936                  * the driver for non nested interrupt handling by the
937                  * dummy function which warns when called.
938                  */
                    /*
                     * irq_nested_primary_handler将打印警告信息，并返回IRQ_NONE
                     */
939                 new->handler = irq_nested_primary_handler;
940         } else {
                    /* 
                     * 检查要注册的irq_desc是否支持线程化中断，即检查其
                     * status_use_accessors的_IRQ_NOTHREAD是否置位，若
                     * 置位，则不支持线程化中断
                     */
941                 if (irq_settings_can_thread(desc))
                    /*
                     * irq_setup_forced_threading将设置irqaction->flags的
                     * IRQF_ONESHOT，该标志表明是在中断线程执行完后再打
                     * 开该中断， 若不设置这个位，则会在中断线程之前打
                     * 开中断，则有可能一直处理中断，而不去处理中断线程。
                     * 然后若new->thread_fn为NULL设置：
                     * 线程函数thread_fn将执行真正的中断处理
                     * if (!new->thread_fn) 
                     * {
                         set_bit(IRQTF_FORCED_THREAD, &new->thread_flags);
                         new->thread_fn = new->handler;
                         new->handler = irq_default_primary_handler;
                       }
                     */
942                         irq_setup_forced_threading(new);
943         }
944 
945         /*
946          * Create a handler thread when a thread function is supplied
947          * and the interrupt does not nest into another interrupt
948          * thread.
949          */
950         if (new->thread_fn && !nested) {
951                 struct task_struct *t;
952                 /* 
                     * 创建一个内核线程，该线程将从irq_thread函数开始执行，
                     * irq_thread的参数为irqaction *new，内核线程名字由
                     * irq/%d-%s指定，irq_thread函数将会执行注册的中断处理
                     * 函数
                     * 每一个请求的IRQ都将创建一个kthread，如果是共享中断，
                     * 则每个参与共享的IRQ都有一个kthread
                     */
953                 t = kthread_create(irq_thread, new, "irq/%d-%s", irq,
954                                    new->name);
955                 if (IS_ERR(t)) {
956                         ret = PTR_ERR(t);
957                         goto out_mput;
958                 }
959                 /*
960                  * We keep the reference to the task struct even if
961                  * the thread dies to avoid that the interrupt code
962                  * references an already freed task_struct.
963                  */
                    /*
                     * 增加task_struct t的引用计数，防止创建的内核线程死亡
                     * 后中断代码仍然引用被释放的task_struct
                     */
964                 get_task_struct(t);
965                 new->thread = t;
966                 /*
967                  * Tell the thread to set its affinity. This is
968                  * important for shared interrupt handlers as we do
969                  * not invoke setup_affinity() for the secondary
970                  * handlers as everything is already set up. Even for
971                  * interrupts marked with IRQF_NO_BALANCE this is
972                  * correct as we want the thread to move to the cpu(s)
973                  * on which the requesting code placed the interrupt.
974                  */
                    /*
                     * 设置线程的处理器亲和性，CPU 亲和性（affinity） 就
                     * 是进程要在某个给定的 CPU 上尽量长时间地运行而不被
                     * 迁移到其他处理器的倾向性
                     */
975                 set_bit(IRQTF_AFFINITY, &new->thread_flags);
976         }
977         /*
             *  分配一个CPU位图，GFP_KERNEL为用kmalloc_node分配
             *  内存时的标志，出错返回-ENOMEM（没有内存可供分配）
             */
978         if (!alloc_cpumask_var(&mask, GFP_KERNEL)) {
979                 ret = -ENOMEM;
980                 goto out_thread;
981         }
982 
983         /*
984          * Drivers are often written to work w/o knowledge about the
985          * underlying irq chip implementation, so a request for a
986          * threaded irq without a primary hard irq context handler
987          * requires the ONESHOT flag to be set. Some irq chips like
988          * MSI based interrupts are per se one shot safe. Check the
989          * chip flags, so we can avoid the unmask dance at the end of
990          * the threaded handler for those.
991          */
            /*
             * 若中断控制器芯片设置了IRQCHIP_ONESHOT_SAFE，则表明中断控制器
             * 在中断线程执行完之前可以打开中断。
             */
992         if (desc->irq_data.chip->flags & IRQCHIP_ONESHOT_SAFE)
993                 new->flags &= ~IRQF_ONESHOT;
994 
995         /*
996          * The following block of code has to be executed atomically
997          */
            /*
             * raw_spin_lock_irqsave首先保存中断状态，然后禁止本地中断
             * 并加锁desc->lock
             */
998         raw_spin_lock_irqsave(&desc->lock, flags);
999         old_ptr = &desc->action;
1000        old = *old_ptr;
1001         if (old) {
1002                 /*
1003                  * Can't share interrupts unless both agree to and are
1004                  * the same type (level, edge, polarity). So both flag
1005                  * fields must have IRQF_SHARED set and the bits which
1006                  * set the trigger type must match. Also all must
1007                  * agree on ONESHOT.
1008                  */
                     /*
                      * old不为空，则说明对应一个中断号，有多个中断处理程序
                      * 即为共享中断，那么应该检查即将注册的中断处理程序和原
                      * 有的处理程序之间标有些标志是否一致(例如触发方式等)
                      * 共享中断也可以实现中断线程化
                      * [patch 2/5] genirq: Allow shared oneshot interrupts
                      */
1009                 if (!((old->flags & new->flags) & IRQF_SHARED) ||
1010                     ((old->flags ^ new->flags) & IRQF_TRIGGER_MASK) ||
1011                     ((old->flags ^ new->flags) & IRQF_ONESHOT))
1012                         goto mismatch;
1013 
1014                 /* All handlers must agree on per-cpuness */
1015                 if ((old->flags & IRQF_PERCPU) !=
1016                     (new->flags & IRQF_PERCPU))
1017                         goto mismatch;
1018 
1019                 /* add new interrupt at end of irq queue */
                     /* 
                      * 将新的中断处理程序添加到中断处理链的末尾，
                      * 这里事实上还没有添加，只是找到末尾位置，并且
                      * 查看thread_mask中是否有空余的位来标示新的中断
                      */
1020                 do {
1021                         /*
1022                          * Or all existing action->thread_mask bits,
1023                          * so we can find the next zero bit for this
1024                          * new action.
1025                          */
1026                         thread_mask |= old->thread_mask;
1027                         old_ptr = &old->next;
1028                         old = *old_ptr;
1029                 } while (old);
                     /*共享中断，设置shared = 1*/
1030                 shared = 1;
1031         }
1032 
1033         /*
1034          * Setup the thread mask for this irqaction for ONESHOT. For
1035          * !ONESHOT irqs the thread mask is 0 so we can avoid a
1036          * conditional in irq_wake_thread().
1037          */
1038         if (new->flags & IRQF_ONESHOT) {
1039                 /*
1040                  * Unlikely to have 32 resp 64 irqs sharing one line,
1041                  * but who knows.
                      * 如果thread_mask中没有空余的位，则无法注册新的中断，
                      * 返回-EBUSY
1042                  */
1043                 if (thread_mask == ~0UL) {
1044                         ret = -EBUSY;
1045                         goto out_mask;
1046                 }
1047                 /*
1048                  * The thread_mask for the action is or'ed to
1049                  * desc->thread_active to indicate that the
1050                  * IRQF_ONESHOT thread handler has been woken, but not
1051                  * yet finished. The bit is cleared when a thread
1052                  * completes. When all threads of a shared interrupt
1053                  * line have completed desc->threads_active becomes
1054                  * zero and the interrupt line is unmasked. See
1055                  * handle.c:irq_wake_thread() for further information.
1056                  *
1057                  * If no thread is woken by primary (hard irq context)
1058                  * interrupt handlers, then desc->threads_active is
1059                  * also checked for zero to unmask the irq line in the
1060                  * affected hard irq flow handlers
1061                  * (handle_[fasteoi|level]_irq).
1062                  *
1063                  * The new action gets the first zero bit of
1064                  * thread_mask assigned. See the loop above which or's
1065                  * all existing action->thread_mask bits.
1066                  */
                      /*
                       * ffz找到thread_mask中的第一个zero bit，将new->thread_mask
                       * 设置为这个空闲位，
                       */
1067                 new->thread_mask = 1 << ffz(thread_mask);
1068 
1069         } else if (new->handler == irq_default_primary_handler &&
1070                    !(desc->irq_data.chip->flags & IRQCHIP_ONESHOT_SAFE)) {
1071                 /*
1072                  * The interrupt was requested with handler = NULL, so
1073                  * we use the default primary handler for it. But it
1074                  * does not have the oneshot flag set. In combination
1075                  * with level interrupts this is deadly, because the
1076                  * default primary handler just wakes the thread, then
1077                  * the irq lines is reenabled, but the device still
1078                  * has the level irq asserted. Rinse and repeat....
1079                  *
1080                  * While this works for edge type interrupts, we play
1081                  * it safe and reject unconditionally because we can't
1082                  * say for sure which type this interrupt really
1083                  * has. The type flags are unreliable as the
1084                  * underlying chip implementation can override them.
1085                  */
1086                 pr_err("Threaded irq requested with handler=NULL and !ONESHOT for irq %d\n",
1087                        irq);
1088                 ret = -EINVAL;
1089                 goto out_mask;
1090         }
1091         /* share为0，说明新注册的是此中断号的第一个中断处理程序*/
1092         if (!shared) {
1093                 init_waitqueue_head(&desc->wait_for_threads);
1094 
1095                 /* Setup the type (level, edge polarity) if configured: */
1096                 if (new->flags & IRQF_TRIGGER_MASK) {
1097                         ret = __irq_set_trigger(desc, irq,
1098                                         new->flags & IRQF_TRIGGER_MASK);
1099 
1100                         if (ret)
1101                                 goto out_mask;
1102                 }
1103 
1104                 desc->istate &= ~(IRQS_AUTODETECT | IRQS_SPURIOUS_DISABLED | \
1105                                   IRQS_ONESHOT | IRQS_WAITING);
1106                 irqd_clear(&desc->irq_data, IRQD_IRQ_INPROGRESS);
1107 
1108                 if (new->flags & IRQF_PERCPU) {
1109                         irqd_set(&desc->irq_data, IRQD_PER_CPU);
1110                         irq_settings_set_per_cpu(desc);
1111                 }
1112 
1113                 if (new->flags & IRQF_ONESHOT)
1114                         desc->istate |= IRQS_ONESHOT;
1115 
1116                 if (irq_settings_can_autoenable(desc))
1117                         irq_startup(desc, true);
1118                 else
1119                         /* Undo nested disables: */
1120                         desc->depth = 1;
1121 
1122                 /* Exclude IRQ from balancing if requested */
1123                 if (new->flags & IRQF_NOBALANCING) {
1124                         irq_settings_set_no_balancing(desc);
1125                         irqd_set(&desc->irq_data, IRQD_NO_BALANCING);
1126                 }
1127 
1128                 /* Set default affinity mask once everything is setup */
1129                 setup_affinity(irq, desc, mask);
1130 
1131         } else if (new->flags & IRQF_TRIGGER_MASK) {
1132                 unsigned int nmsk = new->flags & IRQF_TRIGGER_MASK;
1133                 unsigned int omsk = irq_settings_get_trigger_mask(desc);
1134 
1135                 if (nmsk != omsk)
1136                         /* hope the handler works with current  trigger mode */
1137                         pr_warning("irq %d uses trigger mode %u; requested %u\n",
1138                                    irq, nmsk, omsk);
1139         }
1140         /*
              * 在这里将新的中断处理程序添加到desc中，如果是共享中断则添加到
              * 链表末尾  
              */
1141         new->irq = irq;
1142         *old_ptr = new;
1143 
1144         /* Reset broken irq detection when installing new handler */
1145         desc->irq_count = 0;
1146         desc->irqs_unhandled = 0;
1147 
1148         /*
1149          * Check whether we disabled the irq via the spurious handler
1150          * before. Reenable it and give it another chance.
1151          */
1152         if (shared && (desc->istate & IRQS_SPURIOUS_DISABLED)) {
1153                 desc->istate &= ~IRQS_SPURIOUS_DISABLED;
1154                 __enable_irq(desc, irq, false);
1155         }
1156 
1157         raw_spin_unlock_irqrestore(&desc->lock, flags);
1158 
1159         /*
1160          * Strictly no need to wake it up, but hung_task complains
1161          * when no hard interrupt wakes the thread up.
1162          */
1163         if (new->thread)
1164                 wake_up_process(new->thread);
1165         /* 在proc文件系统中建立目录proc/irq/NUM */
1166         register_irq_proc(irq, desc);
1167         new->dir = NULL;
             /* 生成proc/irq/NUM/name */
1168         register_handler_proc(irq, new);
1169         free_cpumask_var(mask);
1170 
1171         return 0;
1172 
1173 mismatch:
1174         if (!(new->flags & IRQF_PROBE_SHARED)) {
1175                 pr_err("Flags mismatch irq %d. %08x (%s) vs. %08x (%s)\n",
1176                        irq, new->flags, new->name, old->flags, old->name);
1177 #ifdef CONFIG_DEBUG_SHIRQ
1178                 dump_stack();
1179 #endif
1180         }
1181         ret = -EBUSY;
1182 
1183 out_mask:
1184         raw_spin_unlock_irqrestore(&desc->lock, flags);
1185         free_cpumask_var(mask);
1186 
1187 out_thread:
1188         if (new->thread) {
1189                 struct task_struct *t = new->thread;
1190 
1191                 new->thread = NULL;
1192                 kthread_stop(t);
1193                 put_task_struct(t);
1194         }
1195 out_mput:
1196         module_put(desc->owner);
1197         return ret;
1198 }


888 static void irq_setup_forced_threading(struct irqaction *new)
889 {
	/*
            Date	Wed, 23 Feb 2011 23:52:23 -0000
            From	Thomas Gleixner <>
            Subject	 [patch 5/5] genirq: Provide forced interrupt threading

      Add a commandline parameter "threadirqs" which forces all 
	  interrupts except those marked IRQF_NO_THREAD to run threaded. 
	  That's mostly a debug option to allow retrieving better debug 
	  data from crashing interrupt handlers. If "threadirqs" is not 
	  enabled on the kernel command line, then there is no impact in 
	  the interrupt hotpath.
      Architecture code needs to select CONFIG_IRQ_FORCED_THREADING 
	  after marking the interrupts which cant be threaded IRQF_NO_THREAD. 
	  All interrupts which have IRQF_TIMER set are implict marked
      IRQF_NO_THREAD. Also all PER_CPU interrupts are excluded.
        IRQF_ONESHOT - Interrupt is not reenabled after the hardirq handler 
	  finished. Used by threaded interrupts which need to keep the irq 
	  line disabled until the threaded handler has been run.
        
     */
890     if (!force_irqthreads)
891			return;
     /* 若已经设置过IRQF_ONESHOT，说明已经被线程化了，不用继续处理 */
892		if (new->flags & (IRQF_NO_THREAD | IRQF_PERCPU | IRQF_ONESHOT))
893			return;
894	
895		new->flags |= IRQF_ONESHOT;
896	
897		if (!new->thread_fn) {
898			set_bit(IRQTF_FORCED_THREAD, &new->thread_flags);
899			new->thread_fn = new->handler;
900			new->handler = irq_default_primary_handler;
901		}
902	}


/********************************************************************
 *                     创建内核中断线程的过程
 *
 * t = kthread_create(irq_thread, new, "irq/%d-%s", irq,new->name);
 *
 ********************************************************************/
13	#define kthread_create(threadfn, data, namefmt, arg...) \
14      kthread_create_on_node(threadfn, data, -1, namefmt, ##arg)

199	/**
200	 * kthread_create_on_node - create a kthread.
201	 * @threadfn: the function to run until signal_pending(current).
202	 * @data: data ptr for @threadfn.
203	 * @node: memory node number.
204	 * @namefmt: printf-style name for the thread.
205	 *
206	 * Description: This helper function creates and names a kernel
207	 * thread.  The thread will be stopped: use wake_up_process() to start
208	 * it.  See also kthread_run().
209	 *
210	 * If thread is going to be bound on a particular cpu, give its node
211	 * in @node, to get NUMA affinity for kthread stack, or else give -1.
212	 * When woken, the thread will run @threadfn() with @data as its
213	 * argument. @threadfn() can either call do_exit() directly if it is a
214	 * standalone thread for which no one will call kthread_stop(), or
215	 * return when 'kthread_should_stop()' is true (which means
216	 * kthread_stop() has been called).  The return value should be zero
217	 * or a negative error number; it will be passed to kthread_stop().
218	 *
219	 * Returns a task_struct or ERR_PTR(-ENOMEM).
220	 */
221	struct task_struct *kthread_create_on_node(int (*threadfn)(void *data),
222						   void *data, int node,
223						   const char namefmt[],
224						   ...)
225	{
226		struct kthread_create_info create;
227	
228		create.threadfn = threadfn;
229		create.data = data;
230		create.node = node;
231		init_completion(&create.done);
232	
233		spin_lock(&kthread_create_lock);
234		list_add_tail(&create.list, &kthread_create_list);
235		spin_unlock(&kthread_create_lock);
236	
237		wake_up_process(kthreadd_task);
238		wait_for_completion(&create.done);
239	
240		if (!IS_ERR(create.result)) {
241			static const struct sched_param param = { .sched_priority = 0 };
242			va_list args;
243	
244			va_start(args, namefmt);
245			vsnprintf(create.result->comm, sizeof(create.result->comm),
246				  namefmt, args);
247			va_end(args);
248			/*
249			 * root may have changed our (kthreadd's) priority or CPU mask.
250			 * The kernel thread should not inherit these properties.
251			 */
252			sched_setscheduler_nocheck(create.result, SCHED_NORMAL, &param);
253			set_cpus_allowed_ptr(create.result, cpu_all_mask);
254		}
255		return create.result;
256	}
257	EXPORT_SYMBOL(kthread_create_on_node);

/*
 *  当启用中断线程化时，创建的内核线程将运行irq_thread函数 
 */
836 /*
837  * Interrupt handler thread
838  */
204 /**
205  * struct callback_head - callback structure for use with RCU and task_work
206  * @next: next update requests in a list
207  * @func: actual update function to call after the grace period.
208  */
209 struct callback_head {
210         struct callback_head *next;
211         void (*func)(struct callback_head *head);
212 };
213 #define rcu_head callback_head
214 

/* @data： 将要调用的中断处理程序irqaction */
839 static int irq_thread(void *data)
840 {
            /* on_exit_work用来处理这个线程退出时的工作 */
841         struct callback_head on_exit_work;
842         static const struct sched_param param = {
843                 .sched_priority = MAX_USER_RT_PRIO/2,
844         };
845         struct irqaction *action = data;
846         struct irq_desc *desc = irq_to_desc(action->irq);
847         irqreturn_t (*handler_fn)(struct irq_desc *desc,
848                         struct irqaction *action);
849         /*
             *  若没有显示的要使用线程化中断，则handler_fn设置为
             *  irq_forced_thread_fn，否则置为irq_thread_fn，这两个
             *  函数都将执行action->thread_fn，所不同的是
             *  irq_forced_thread_fn在执行过程中会软中断和下半部的
             *  执行
             */
850         if (force_irqthreads && test_bit(IRQTF_FORCED_THREAD,
851                                         &action->thread_flags))
852                 handler_fn = irq_forced_thread_fn;
853         else
854                 handler_fn = irq_thread_fn;
855         /* 
             *  sched_setscheduler - change the scheduling policy 
             *  and/or RT priority of a thread 
             */
856         sched_setscheduler(current, SCHED_FIFO, &param);
857 
858         init_task_work(&on_exit_work, irq_thread_dtor);
859         task_work_add(current, &on_exit_work, false);
860 
861         irq_thread_check_affinity(desc, action);
862         /* 
             * 等待中断将本线程唤醒，或者线程被终止则退出，若
             * irq_wait_for_interrupt返回0，则继续，若返回
             * -1，则准备终止线程
             */
863         while (!irq_wait_for_interrupt(action)) {
864                 irqreturn_t action_ret;
865                 /* 检查中断亲和性是否被重新设置，如果设置了，则将线程迁移到相应的CPU上 */
866                 irq_thread_check_affinity(desc, action);
867                 /* 
                     * 在这里我们将执行注册的中断函数，参看L849 handler_fn
                     * 注释
                     */
868                 action_ret = handler_fn(desc, action);
869                 if (!noirqdebug)
870                         note_interrupt(action->irq, desc, action_ret);

871                 /* 执行完中断处理后，唤醒本中断上的等待队列 */
872                 wake_threads_waitq(desc);
873         }
874 
875         /*
876          * This is the regular exit path. __free_irq() is stopping the
877          * thread via kthread_stop() after calling
878          * synchronize_irq(). So neither IRQTF_RUNTHREAD nor the
879          * oneshot mask bit can be set. We cannot verify that as we
880          * cannot touch the oneshot mask at this point anymore as
881          * __setup_irq() might have given out currents thread_mask
882          * again.
883          */
884         task_work_cancel(current, irq_thread_dtor);
885         return 0;
886 }

/*
 * [PATCH v3 3/3] genirq: reimplement exit_irq_thread() 
 *                        hook via task_work_queue()
   exit_irq_thread() and task->irq_thread are needed to handle
   the unexpected (and unlikely) exit of irq-thread.

   We can use task_work instead and make this all private to
   kernel/irq/manage.c, simplification plus micro-optimization.

   1. rename exit_irq_thread() to irq_thread_dtor(), make it
      static, and move it up before irq_thread().

   2. change irq_thread() to do task_queue_work(irq_thread_dtor)
      at the start and task_work_cancel() before return.

      tracehook_notify_resume() can never play with kthreads,
      only do_exit()->exit_task_work() can call the callback
      and this is what we want.

   3. remove task_struct->irq_thread and the special hook
      in do_exit().
*/
  7 typedef void (*task_work_func_t)(struct callback_head *);
  8 
  9 static inline void
 10 init_task_work(struct callback_head *twork, task_work_func_t func)
 11 {
 12         twork->func = func;
 13 }

    /* 中断线程退出时的处理函数 */
809 static void irq_thread_dtor(struct callback_head *unused)
810 {
811         struct task_struct *tsk = current;
812         struct irq_desc *desc;
813         struct irqaction *action;
814 
815         if (WARN_ON_ONCE(!(current->flags & PF_EXITING)))
816                 return;
817 
818         action = kthread_data(tsk);
819 
820         pr_err("exiting task \"%s\" (%d) is an active IRQ thread (irq %d)\n",
821                tsk->comm, tsk->pid, action->irq);
822 
823 
824         desc = irq_to_desc(action->irq);
825         /*
826          * If IRQTF_RUNTHREAD is set, we need to decrement
827          * desc->threads_active and wake possible waiters.
828          */
829         if (test_and_clear_bit(IRQTF_RUNTHREAD, &action->thread_flags))
830                 wake_threads_waitq(desc);
831 
832         /* Prevent a stale desc->threads_oneshot */
833         irq_finalize_oneshot(desc, action);
834 }


    /* 将一个线程task添加到回调函数work中 */
  7 int
  8 task_work_add(struct task_struct *task, struct callback_head *work, bool notify)
  9 {
 10         struct callback_head *head;
 11 
 12         do {
 13                 head = ACCESS_ONCE(task->task_works);
 14                 if (unlikely(head == &work_exited))
 15                         return -ESRCH;
 16                 work->next = head;
 17         } while (cmpxchg(&task->task_works, head, work) != head);
 18 
 19         if (notify)
 20                 set_notify_resume(task);
 21         return 0;
 22 }

655 static int irq_wait_for_interrupt(struct irqaction *action)
656 {
657         set_current_state(TASK_INTERRUPTIBLE);
658         /* 
             * 判断线程是否被停止，调用kthread_stop停止线程时，
             * 会将should_stop设为1，kthread_should_stop返回线程的
             * should_stop
             */
659         while (!kthread_should_stop()) {
660                 /* 
                     * IRQTF_RUNTHREAD - signals that the interrupt 
                     * handler thread should run
                     */
661                 if (test_and_clear_bit(IRQTF_RUNTHREAD,
662                                        &action->thread_flags)) {
663                         __set_current_state(TASK_RUNNING);
664                         return 0;
665                 }
                    /* 如果没有设置IRQTF_RUNTHREAD，则调用其他线程运行*/
666                 schedule();
667                 set_current_state(TASK_INTERRUPTIBLE);
668         }
669         __set_current_state(TASK_RUNNING);
670         return -1;
671 }

