#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "intf.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 * 1024 * 1024); /* 16 MB */
} events SEC(".maps");

SEC("tp_btf/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt,
	     struct task_struct *prev, struct task_struct *next)
{
	struct event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = SCHED_SWITCH_EVENT;
	e->cpu = bpf_get_smp_processor_id();
	e->ts = bpf_ktime_get_ns();
	e->prev_pid = BPF_CORE_READ(prev, pid);
	e->next_pid = BPF_CORE_READ(next, pid);
	e->prev_tgid = BPF_CORE_READ(prev, tgid);
	e->next_tgid = BPF_CORE_READ(next, tgid);
	BPF_CORE_READ_STR_INTO(&e->prev_comm, prev, comm);
	BPF_CORE_READ_STR_INTO(&e->next_comm, next, comm);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
