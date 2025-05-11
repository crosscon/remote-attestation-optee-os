#include <string.h>
#include <kernel/pseudo_ta.h>
#include <pta_memread.h>

//#include <tee_internal_api.h>
//#include <tee_internal_api_extensions.h>
#include <crypto/crypto.h>
#include <tee_api_types.h>

#define PTA_NAME "memread.pta"


#define MEMORY_REGION_START_ADDR  0x00
#define MEMORY_REGION_SIZE        0x10


TEE_Result get_pattern_base_address_in_memory_region(size_t memory_start, size_t memory_size, const char* pattern, size_t pattern_size, size_t test_size, char* memory_to_hash) {
    for (size_t i = memory_start; i < memory_start + memory_size - pattern_size - test_size + 1; i++) {
        char* offset = (char*) i;
        if (memcmp(offset, pattern, pattern_size) == 0) {
            memory_to_hash = offset;
            return TEE_SUCCESS;
        }
    }

    return TEE_ERROR_ITEM_NOT_FOUND;
}


static TEE_Result invoke_command(
    void* sess_ctx,
    uint32_t cmd_id,
    uint32_t param_types,
    TEE_Param params[TEE_NUM_PARAMS]
) {
    TEE_Result res;

    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT
    );

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    uint8_t vm_index = (uint8_t) params[0].value.a;

    const char* input_pattern = (const char*) params[1].memref.buffer;
    size_t input_pattern_size = params[1].memref.size;

    size_t memory_region_under_test_size = params[2].value.a;

    char* output_buf = (char*) params[3].memref.buffer;
    size_t output_buf_size = params[3].memref.size;

    char* memory_region_under_test;
    res = get_pattern_base_address_in_memory_region(MEMORY_REGION_START_ADDR, MEMORY_REGION_SIZE, input_pattern, input_pattern_size, memory_region_under_test_size, memory_region_under_test);
    if (res != TEE_SUCCESS)
        return res;

    struct crypto_hash_ctx* ctx = NULL;
    res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA512);
    if (res != TEE_SUCCESS)
        return res;

    res = crypto_hash_init(ctx);
    if (res != TEE_SUCCESS)
        goto out;

    res = crypto_hash_update(ctx, memory_region_under_test, memory_region_under_test_size);
    if (res != TEE_SUCCESS)
        goto out;

    res = crypto_hash_final(ctx, output_buf, output_buf_size);

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
