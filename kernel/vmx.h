#include <linux/io.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include "linux/cpumask.h"
#include "linux/gfp.h"
#include "linux/threads.h"
#include "linux/types.h"
#include "asm/perf_event.h"
#include "asm/vmx.h"

int vmx_setup(void);
void vmx_teardown(void);

