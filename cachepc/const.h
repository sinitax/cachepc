#pragma once

#define L1_ASSOC 8
#define L1_LINESIZE 64
#define L1_SETS 64
#define L1_SIZE (L1_SETS * L1_ASSOC * L1_LINESIZE)
#define L1_LINES (L1_SETS * L1_ASSOC)

#define CPC_ISOLCPU 2

#define CPC_L1MISS_PMC 0
#define CPC_RETINST_PMC 1

#define CPC_VMSA_MAGIC_ADDR ((void *) 0xC0FFEE)

#define KVM_HC_CPC_VMMCALL_SIGNAL 0xEE01
#define KVM_HC_CPC_VMMCALL_EXIT 0xEE02

#define CPC_CL_NEXT_OFFSET 0
#define CPC_CL_PREV_OFFSET 8
#define CPC_CL_COUNT_OFFSET 16

/* APIC divisor determines how much time is added per increment.
 * A large divisor decreases the counter slower, which means more time
 * is added for each increment, possiblpy skipping whole instructions */
#define CPC_APIC_TIMER_TDCR APIC_TDR_DIV_1
#define CPC_APIC_TIMER_SOFTDIV 1
#define CPC_APIC_TIMER_MIN (20 * CPC_APIC_TIMER_SOFTDIV)

#define CPC_EVENT_BATCH_MAX 1000

#define CPC_LOGLVL_INFO 1
#define CPC_LOGLVL_DBG 2
