54	struct nl_portid_hash {
55		struct hlist_head	*table;
56		unsigned long		rehash_time;
57	
58		unsigned int		mask;
59		unsigned int		shift;
60	
61		unsigned int		entries;
62		unsigned int		max_shift;
63	
64		u32			rnd;
65	};
66	
67	struct netlink_table {
68		struct nl_portid_hash	hash;
69		struct hlist_head	mc_list;
70		struct listeners __rcu	*listeners;
71		unsigned int		flags;
72		unsigned int		groups;
73		struct mutex		*cb_mutex;
74		struct module		*module;
75		void			(*bind)(int group);
76		bool			(*compare)(struct net *net, struct sock *sock);
77		int			registered;
78	};
79	
    /* netlink支持的所有proto都保存在一个数组nl_table中 */
   /*
     针对特定的一个proto:
     hash: 所有的proto类型的netlink socket 都放到这个hash链表里。
     mc_list: hash链表。记录希望监听组播消息的netlink socket.
     listeners: 记录哪些group被监听, 一个group占1位.
     nl_noroot: todo!
     groups: 被监听的group的总个数
     cb_mutex: callback 函数用到的锁
     module: 在lsm模式下使用（不严格）。
     register: 是否被注册（占用）。
   */
80	extern struct netlink_table *nl_table;
81	extern rwlock_t nl_table_lock;	



3040	static int __init netlink_proto_init(void)
3041	{
3042		int i;
3043		unsigned long limit;
3044		unsigned int order;
/*
1139	
1140	static struct proto netlink_proto = {
1141		.name	  = "NETLINK",
1142		.owner	  = THIS_MODULE,
1143		.obj_size = sizeof(struct netlink_sock),
1144	};
将netlink_proto注册到proto_list中
proto_list是一个全局的静态链表，inet域支持的所有协议
全部在这个链表中，但这个链表在协议栈中并没有太大用途，
它只是用于在/proc/net/protocols文件中输出当前系统所支持的所有协
*/
3045		int err = proto_register(&netlink_proto, 0);
3046	
3047		if (err != 0)
3048			goto out;
3049	
3050		BUILD_BUG_ON(sizeof(struct netlink_skb_parms) > FIELD_SIZEOF(struct sk_buff, cb));
3051	    /* MAXZ_LINKS == 32，分配32个netlink_table结构的存储空间 */
3052		nl_table = kcalloc(MAX_LINKS, sizeof(*nl_table), GFP_KERNEL);
3053		if (!nl_table)
3054			goto panic;
3055	    /* totalram_pages：内核可以使用的所有物理内存的大小，无法使用的不计在内 */
3056		if (totalram_pages >= (128 * 1024))
3057			limit = totalram_pages >> (21 - PAGE_SHIFT);
3058		else
3059			limit = totalram_pages >> (23 - PAGE_SHIFT);
3060	    /* 返回最高有效位的序号（从1开始），32的最高有效位序号为6（100000）*/
3061		order = get_bitmask_order(limit) - 1 + PAGE_SHIFT;
3062		limit = (1UL << order) / sizeof(struct hlist_head);
3063		order = get_bitmask_order(min(limit, (unsigned long)UINT_MAX)) - 1;
3064	    /* 初始化nl_table */
3065		for (i = 0; i < MAX_LINKS; i++) {
3066			struct nl_portid_hash *hash = &nl_table[i].hash;
3067	
3068			hash->table = nl_portid_hash_zalloc(1 * sizeof(*hash->table));
3069			if (!hash->table) {
	                /* 若第i次分配失败，则释放前面i-1次分配的内存 */
3070				while (i-- > 0)
3071					nl_portid_hash_free(nl_table[i].hash.table,
3072							 1 * sizeof(*hash->table));
3073				kfree(nl_table);
3074				goto panic;
3075			}
3076			hash->max_shift = order;
3077			hash->shift = 0;
3078			hash->mask = 0;
3079			hash->rehash_time = jiffies;
3080	        /* netlink_compare函数使得属于同一User命名空间的netlink socket通信*/
3081			nl_table[i].compare = netlink_compare;
3082		}
3083	
3084		INIT_LIST_HEAD(&netlink_tap_all);
3085	    /* 添加对NETLINK_USERSOCK支持 */
3086		netlink_add_usersock_entry();
3087	    /*
2993	static const struct net_proto_family netlink_family_ops = {
2994		.family = PF_NETLINK,
2995		.create = netlink_create,
2996		.owner	= THIS_MODULE,	      (for consistency 8) 
2997	    };

             将NETLINK注册到socket中，这样可以通过socket进行NETLINK通信
             */
3088		sock_register(&netlink_family_ops);
            /* 注册网络命名空间的子系统 */
3089		register_pernet_subsys(&netlink_net_ops);
3090		/* The netlink device handler may be needed early. */
3091		rtnetlink_init();
3092	out:
3093		return err;
3094	panic:
3095		panic("netlink_init: Cannot allocate nl_table\n");
3096	}
3097	
3098	core_initcall(netlink_proto_init);
3099	


3015	static void __init netlink_add_usersock_entry(void)
3016	{
3017		struct listeners *listeners;
3018		int groups = 32;
3019	
3020		listeners = kzalloc(sizeof(*listeners) + NLGRPSZ(groups), GFP_KERNEL);
3021		if (!listeners)
3022			panic("netlink_add_usersock_entry: Cannot allocate listeners\n");
3023	
3024		netlink_table_grab();
3025	
3026		nl_table[NETLINK_USERSOCK].groups = groups;
3027		rcu_assign_pointer(nl_table[NETLINK_USERSOCK].listeners, listeners);
3028		nl_table[NETLINK_USERSOCK].module = THIS_MODULE;
3029		nl_table[NETLINK_USERSOCK].registered = 1;
3030		nl_table[NETLINK_USERSOCK].flags = NL_CFG_F_NONROOT_SEND;
3031	   
3032		netlink_table_ungrab();
3033	}


2560	/**
2561	 *	sock_register - add a socket protocol handler
2562	 *	@ops: description of protocol
2563	 *
2564	 *	This function is called by a protocol handler that wants to
2565	 *	advertise its address family, and have it linked into the
2566	 *	socket interface. The value ops->family coresponds to the
2567	 *	socket system call protocol family.
2568	 */
2569	int sock_register(const struct net_proto_family *ops)
2570	{
2571		int err;
2572	
2573		if (ops->family >= NPROTO) {
2574			printk(KERN_CRIT "protocol %d >= NPROTO(%d)\n", ops->family,
2575			       NPROTO);
2576			return -ENOBUFS;
2577		}
2578	
2579		spin_lock(&net_family_lock);
2580		if (rcu_dereference_protected(net_families[ops->family],
2581					      lockdep_is_held(&net_family_lock)))
2582			err = -EEXIST;
2583		else {
2584			rcu_assign_pointer(net_families[ops->family], ops);
2585			err = 0;
2586		}
2587		spin_unlock(&net_family_lock);
2588	
2589		printk(KERN_INFO "NET: Registered protocol family %d\n", ops->family);
2590		return err;
2591	}
2592	EXPORT_SYMBOL(sock_register);



2736	void __init rtnetlink_init(void)
2737	{
2738		if (register_pernet_subsys(&rtnetlink_net_ops))
2739			panic("rtnetlink_init: cannot initialize rtnetlink\n");
2740	
2741		register_netdevice_notifier(&rtnetlink_dev_notifier);
2742	
2743		rtnl_register(PF_UNSPEC, RTM_GETLINK, rtnl_getlink,
2744			      rtnl_dump_ifinfo, rtnl_calcit);
2745		rtnl_register(PF_UNSPEC, RTM_SETLINK, rtnl_setlink, NULL, NULL);
2746		rtnl_register(PF_UNSPEC, RTM_NEWLINK, rtnl_newlink, NULL, NULL);
2747		rtnl_register(PF_UNSPEC, RTM_DELLINK, rtnl_dellink, NULL, NULL);
2748	
2749		rtnl_register(PF_UNSPEC, RTM_GETADDR, NULL, rtnl_dump_all, NULL);
2750		rtnl_register(PF_UNSPEC, RTM_GETROUTE, NULL, rtnl_dump_all, NULL);
2751	
2752		rtnl_register(PF_BRIDGE, RTM_NEWNEIGH, rtnl_fdb_add, NULL, NULL);
2753		rtnl_register(PF_BRIDGE, RTM_DELNEIGH, rtnl_fdb_del, NULL, NULL);
2754		rtnl_register(PF_BRIDGE, RTM_GETNEIGH, NULL, rtnl_fdb_dump, NULL);
2755	
2756		rtnl_register(PF_BRIDGE, RTM_GETLINK, NULL, rtnl_bridge_getlink, NULL);
2757		rtnl_register(PF_BRIDGE, RTM_DELLINK, rtnl_bridge_dellink, NULL, NULL);
2758		rtnl_register(PF_BRIDGE, RTM_SETLINK, rtnl_bridge_setlink, NULL, NULL);
2759	}



214	/**
215	 * rtnl_register - Register a rtnetlink message type
216	 *
217	 * Identical to __rtnl_register() but panics on failure. This is useful
218	 * as failure of this function is very unlikely, it can only happen due
219	 * to lack of memory when allocating the chain to store all message
220	 * handlers for a protocol. Meant for use in init functions where lack
221	 * of memory implies no sense in continuing.
222	 */
223	void rtnl_register(int protocol, int msgtype,
224			   rtnl_doit_func doit, rtnl_dumpit_func dumpit,
225			   rtnl_calcit_func calcit)
226	{
227		if (__rtnl_register(protocol, msgtype, doit, dumpit, calcit) < 0)
228			panic("Unable to register rtnetlink message handler, "
229			      "protocol = %d, message type = %d\n",
230			      protocol, msgtype);
231	}
232	EXPORT_SYMBOL_GPL(rtnl_register);