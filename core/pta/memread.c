#include <kernel/pseudo_ta.h>
#include <pta_memread.h>

#define PTA_NAME "memread.pta"


static TEE_Result invoke_command(void* sess_ctx __unused, uint32_t cmd_id __unused, uint32_t param_types __unused, TEE_Param params[TEE_NUM_PARAMS] __unused) {
    uint32_t addr_value = 0x10100010;
    uint8_t* addr_ptr = (uint8_t*) addr_value;
    uint8_t value = *addr_ptr;

    return TEE_SUCCESS;
}


pseudo_ta_register(
    .uuid = PTA_MEMREAD_UUID,
    .name = PTA_NAME,
    .flags = PTA_DEFAULT_FLAGS,
    .invoke_command_entry_point = invoke_command
);
