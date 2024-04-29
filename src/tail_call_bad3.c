// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "bpf.h"

__attribute__((section(".maps"), used))
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} map;

__attribute__((section(".maps"), used))
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __array(values, map);
} array_of_maps = {
    .values = { &map },
};

__attribute__((section("xdp_prog"), used)) int
caller(struct xdp_md* ctx)
{
    uint32_t key = 0;
    void* prog_array_map = bpf_map_lookup_elem(&array_of_maps, &key);

    // Should reject as r2 is a pointer to a stack address.
    long error = bpf_tail_call(ctx, &prog_array_map, 0);

    // bpf_tail_call failed at runtime.
    return (int)error;
}

__attribute__((section("xdp_prog/0"), used)) int
callee(struct xdp_md* ctx)
{
    return 42;
}
