#!/usr/bin/python

# This code is modified version of sslsniff.
# https://github.com/iovisor/bcc/blob/master/tools/sslsniff.py
#
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function

import argparse
import json
import sys

import hyperframe.frame
from hpack import Decoder

from sbom_tracer.util.compat import decode

try:
    from bcc import BPF
except ImportError:
    from bpfcc import BPF

# arguments
examples = """examples:
    ./h2sniff              # sniff HTTP/2 data
"""
parser = argparse.ArgumentParser(
    description="Sniff HTTP/2 data",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("--task-id")
args = parser.parse_args()

prog = """
#include <linux/ptrace.h>
#include <linux/sched.h>        /* For TASK_COMM_LEN */
#define MAX_BUF_SIZE 8192
struct probe_SSL_data_t {
        u64 timestamp_ns;
        u32 pid;
        u32 ppid;
        u32 tid;
        u32 uid;
        u32 len;
        int buf_filled;
        char comm[TASK_COMM_LEN];
        u8 buf[MAX_BUF_SIZE];
};
#define BASE_EVENT_SIZE ((size_t)(&((struct probe_SSL_data_t*)0)->buf))
#define EVENT_SIZE(X) (BASE_EVENT_SIZE + ((size_t)(X)))
BPF_PERCPU_ARRAY(ssl_data, struct probe_SSL_data_t, 1);
BPF_PERF_OUTPUT(perf_SSL_write);
int probe_SSL_write(struct pt_regs *ctx, void *ssl, void *buf, int num) {
        int ret;
        u32 zero = 0;
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = pid_tgid;
        u32 uid = bpf_get_current_uid_gid();

        struct probe_SSL_data_t *data = ssl_data.lookup(&zero);
        if (!data)
                return 0;
        data->timestamp_ns = bpf_ktime_get_ns();
        data->pid = pid;
        struct task_struct *task;
        task = (struct task_struct *)bpf_get_current_task();
        data->ppid = task->real_parent->tgid;
        data->tid = tid;
        data->uid = uid;
        data->len = num;
        data->buf_filled = 0;
        bpf_get_current_comm(&data->comm, sizeof(data->comm));
        u32 buf_copy_size = min((size_t)MAX_BUF_SIZE, (size_t)num);
        if (buf != 0)
                ret = BPF_PROBE_READ_FUNC(data->buf, buf_copy_size, buf);
        if (!ret)
                data->buf_filled = 1;
        else
                buf_copy_size = 0;
        perf_SSL_write.perf_submit(ctx, data, EVENT_SIZE(buf_copy_size));
        return 0;
}
"""

bpf_with_bpf_probe_read_user = prog.replace("BPF_PROBE_READ_FUNC", "bpf_probe_read_user")
bpf_with_bpf_probe_read = prog.replace("BPF_PROBE_READ_FUNC", "bpf_probe_read")

ssl_list = [("ssl", "SSL_write"), ("gnutls", "gnutls_record_send"), ("nspr4", "PR_Write"), ("nspr4", "PR_Send")]
exc_count = 0
b = BPF(text=bpf_with_bpf_probe_read_user)
for name, sym in ssl_list:
    try:
        b.attach_uprobe(name=name, sym=sym, fn_name="probe_SSL_write", pid=-1)
    except:
        exc_count += 1

if exc_count == len(ssl_list):
    b = BPF(text=bpf_with_bpf_probe_read)
    for name, sym in ssl_list:
        try:
            b.attach_uprobe(name=name, sym=sym, fn_name="probe_SSL_write", pid=-1)
        except:
            pass

FRAMES = [
    "DATA",
    "HEADERS",
    "PRIORITY",
    "RST_STREAM",
    "SETTINGS",
    "PUSH_PROMISE",
    "PING",
    "GOAWAY",
    "WINDOW_UPDATE",
    "CONTINUATION",
    "ALT_SVC",
]

max_buffer_size = 8192


def get_ppid(pid):
    try:
        with open("/proc/%d/status" % pid) as status:
            for line in status:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except IOError:
        pass
    return 0


def print_event(cpu, data, size):
    global FRAMES
    event = b["perf_SSL_write"].event(data)

    if event.len <= max_buffer_size:
        buf_size = event.len
    else:
        buf_size = max_buffer_size

    if event.buf_filled == 1:
        buf = bytearray(event.buf[:buf_size])
    else:
        buf = b""

    if bytearray(buf)[:24] == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n":
        buf = buf[24:]

    while len(buf) > 9:
        try:
            info = hyperframe.frame.Frame.parse_frame_header(memoryview(bytearray(buf)[:9]))
        except:
            break

        frame = info[0]
        frame_len = info[1]

        if all(flag in frame.flags for flag in ("END_STREAM", "END_HEADERS")):
            ppid = event.ppid if event.ppid > 0 else get_ppid(event.pid)
            print(json.dumps(dict(cmd=decode(event.comm), pid=event.pid,
                                  ppid=ppid, data=Decoder().decode(bytes(buf[9:9 + frame_len])))))
            sys.stdout.flush()

        buf = buf[9 + frame_len:]


b["perf_SSL_write"].open_perf_buffer(print_event, page_cnt=256)

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
