#pragma once

namespace erpc {

static void memory_barrier() { asm volatile("" ::: "memory"); }

}  // namespace erpc
