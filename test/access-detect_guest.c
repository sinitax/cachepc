#include "cachepc/uapi.h"

#include <err.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int
main(int argc, const char **argv)
{
	void *buf;

	buf = NULL;
	if (posix_memalign(&buf, L1_LINESIZE * L1_SETS, L1_LINESIZE * L1_SETS))
		err(1, "memalign");
	memset(buf, 0, L1_LINESIZE * L1_SETS);

	while (1) {
		printf("LOOP\n");
		CPC_DO_VMMCALL(CPC_GUEST_START_TRACK, 0);
		*(uint8_t *)(buf + L1_LINESIZE * 15) = 1;
		CPC_DO_VMMCALL(CPC_GUEST_STOP_TRACK, 0);
	}
}