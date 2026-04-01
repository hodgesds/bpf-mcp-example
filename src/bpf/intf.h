#ifndef __INTF_H
#define __INTF_H

#define TASK_COMM_LEN 16

enum event_type {
	SCHED_SWITCH_EVENT = 1,
};

struct event {
	__u32 type;
	__u32 cpu;
	__u64 ts;
	__u32 prev_pid;
	__u32 next_pid;
	__u32 prev_tgid;
	__u32 next_tgid;
	char prev_comm[TASK_COMM_LEN];
	char next_comm[TASK_COMM_LEN];
};

#endif /* __INTF_H */
