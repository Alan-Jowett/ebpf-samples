// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "bpf.h"

__attribute__((section(".maps"), used))
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} inner_map;

__attribute__((section(".maps"), used))
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __array(values, inner_map);
} array_of_maps = {
    .values = { &inner_map },
};

int func(void* ctx) {
    uint32_t outer_key = 0;
    uint32_t inner_key = 0;
    void *map = bpf_map_lookup_elem(&array_of_maps, &outer_key);
    void *ret = bpf_map_lookup_elem(map, &inner_key);
    if (ret)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}
