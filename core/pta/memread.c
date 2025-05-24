#include "compiler.h"
#include "tee_api_defines.h"
#include <string.h>
#include <kernel/pseudo_ta.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <pta_memread.h>

#include <crypto/crypto.h>
#include <tee_api_types.h>

//#include <config.h>

#define PTA_NAME "memread.pta"

#define MEMREAD_THIS_VM_ID      0


struct vm_mem_mapping {
    size_t phy;
    size_t size;
};

struct vm_mem_mapping_config {
    size_t mappings_num;
    struct vm_mem_mapping* mappings;
};

struct vm_mem_mapping_config config = {
    .mappings_num = 2,
    .mappings = (struct vm_mem_mapping[]){
        [0] = {
            .phy = 0x9000000,
            .size = 0x200000
        },
        [1] = {
            .phy = 0x9200000,
            .size = 0x200000
        }
    }
};


/* int get_shared_ipc(struct vm_config* vm1, struct vm_config* vm2) {
    for (size_t i = 0; i < vm1->platform.ipc_num; i++) {
        for (size_t j = 0; j < vm2->platform.ipc_num; j++) {
            if (vm1->platform.ipcs[i].shmem_id == vm2->platform.ipcs[j].shmem_id)
                return vm1->platform.ipcs[i].shmem_id;
        }
    }

    for (size_t i = 0; i < vm1->children_num; i++) {
        int res = get_shared_ipc(vm1->children[i], vm2);
        if (res >= 0)
            return res;
    }

    for (size_t i = 0; i < vm2->children_num; i++) {
        int res = get_shared_ipc(vm1, vm2->children[i]);
        if (res >= 0)
            return res;
    }

    for (size_t i = 0; i < vm1->children_num; i++) {
        for (size_t j = 0; j < vm2->children_num; j++) {
            int res = get_shared_ipc(vm1->children[i], vm2->children[j]);
            if (res >= 0)
                return res;
        }
    }

    return -1;
}

int get_shmem_base_addr(struct vm_config* vm, size_t shmem_id) {
    for (size_t ipc_idx = 0; ipc_idx < vm->platform.ipc_num; ipc_idx++) {
        struct ipc ipc_ = vm->platform.ipcs[ipc_idx];

        if (ipc_.shmem_id == shmem_id)
            return ipc_.base;
    }

    return -1;
}

int get_shmem_size(struct vm_config* vm, size_t shmem_id) {
    for (size_t ipc_idx = 0; ipc_idx < vm->platform.ipc_num; ipc_idx++) {
        struct ipc ipc_ = vm->platform.ipcs[ipc_idx];

        if (ipc_.shmem_id == shmem_id)
            return ipc_.size;
    }

    return -1;
}

int get_vm_memory_mapping(size_t vm_idx, struct vm_mem_mapping* cfg) {
    if (vm_idx >= config.vmlist_size) {
        return -1;
    }

    struct vm_config* this_vm = config.vmlist[MEMREAD_THIS_VM_ID];
    struct vm_config* other_vm = config.vmlist[vm_idx];

    int shared_ipc = get_shared_ipc(this_vm, other_vm);
    if (shared_ipc < 0)
        return -1;

    int shared_ipc_base = get_shmem_base_addr(this_vm, shared_ipc);
    if (shared_ipc_base < 0)
        return -1;

    int shared_ipc_size = get_shmem_size(this_vm, shared_ipc);
    if (shared_ipc_size < 0)
        return -1;

    cfg->phy = shared_ipc_base;
    cfg->size = shared_ipc_size;

    return 0;
} */


TEE_Result get_pattern_base_address_in_memory_region(
    size_t memory_start,
    size_t memory_size,
    const char* pattern,
    size_t pattern_size,
    size_t test_size,
    char** memory_to_hash
);


TEE_Result get_pattern_base_address_in_memory_region(size_t memory_start, size_t memory_size, const char* pattern, size_t pattern_size, size_t test_size, char** memory_to_hash) {
    for (size_t i = memory_start; i < memory_start + memory_size - pattern_size - test_size + 1; i++) {
        char* offset = (char*) i;
        if (memcmp(offset, pattern, pattern_size) == 0) {
            *memory_to_hash = offset;
            return TEE_SUCCESS;
        }
    }

    return TEE_ERROR_ITEM_NOT_FOUND;
}


static TEE_Result invoke_command(
    void* sess_ctx __maybe_unused,
    uint32_t cmd_id __maybe_unused,
    uint32_t param_types,
    TEE_Param params[TEE_NUM_PARAMS]
) {
    TEE_Result res;

    uint8_t vm_index;
    const char* input_pattern;
    size_t input_pattern_size;
    size_t memory_region_under_test_size;
    char* output_buf;
    size_t output_buf_size;

    struct vm_mem_mapping map;
    void* vaddr;
    char* memory_region_under_test;
    struct crypto_hash_ctx* ctx;

    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT
    );

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    vm_index = (uint8_t) params[0].value.a;

    input_pattern = (const char*) params[1].memref.buffer;
    input_pattern_size = params[1].memref.size;

    memory_region_under_test_size = params[2].value.a;

    output_buf = (char*) params[3].memref.buffer;
    output_buf_size = params[3].memref.size;

    if (vm_index >= config.mappings_num)
        return TEE_ERROR_BAD_PARAMETERS;
    map = config.mappings[vm_index];
    /*if (get_vm_memory_mapping(vm_index, &map) < 0)
        return TEE_ERROR_BAD_PARAMETERS;*/

    vaddr = core_mmu_add_mapping(MEM_AREA_IO_NSEC, map.phy, map.size);
    if (vaddr == NULL)
        vaddr = phys_to_virt(map.phy, MEM_AREA_IO_NSEC, 1);

    if (vaddr == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    res = get_pattern_base_address_in_memory_region((size_t) vaddr, map.size, input_pattern, input_pattern_size, memory_region_under_test_size, &memory_region_under_test);
    if (res != TEE_SUCCESS)
        return res;

    ctx = NULL;
    res = crypto_hash_alloc_ctx((void**) &ctx, TEE_ALG_SHA512);
    if (res != TEE_SUCCESS)
        return res;

    res = crypto_hash_init(ctx);
    if (res != TEE_SUCCESS)
        goto out;

    res = crypto_hash_update(ctx, (const uint8_t*) memory_region_under_test, memory_region_under_test_size);
    if (res != TEE_SUCCESS)
        goto out;

    res = crypto_hash_final(ctx, (uint8_t*) output_buf, output_buf_size);

out:
    crypto_hash_free_ctx(ctx);
    return res;
}


pseudo_ta_register(
    .uuid = PTA_MEMREAD_UUID,
    .name = PTA_NAME,
    .flags = PTA_DEFAULT_FLAGS,
    .invoke_command_entry_point = invoke_command
);
