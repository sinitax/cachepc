#include "cachepc/uapi.h"
#include "kcapi.h"

#include <sys/random.h>
#include <err.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

static uint8_t key[16];

void
printhex(uint8_t *buf, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++)
		printf("%02X", buf[i]);
	printf("\n");
}

int
main(int argc, const char **argv)
{
	struct kcapi_handle *kcapi;
	uint8_t block[128];
	uint8_t *buf;
	size_t n;

	buf = NULL;
	if (posix_memalign((void *)&buf, L1_LINESIZE * L1_SETS, L1_LINESIZE * L1_SETS))
		err(1, "memalign");
	memset(buf, 0, L1_LINESIZE * L1_SETS);

	kcapi = NULL;
	if (kcapi_cipher_init(&kcapi, "ecb(aes)", 0))
		err(1, "kcapi init");

	for (n = 0; n < 16; n++)
		key[n] = (uint8_t) n;

	if (kcapi_cipher_setkey(kcapi, key, sizeof(key)))
		err(1, "kcapi setkey");

	while (1) {
		printf("RUN %li\n", time(NULL));

		memset(block, 0, sizeof(block));
		strncpy((char *) block, "Hello world", sizeof(block));

		printhex(block, sizeof(block));
		n = kcapi_cipher_encrypt(kcapi, block, sizeof(block), NULL,
			block, sizeof(block), KCAPI_ACCESS_HEURISTIC);
		if (n != sizeof(block))
			err(1, "encrypt");
		printhex(block, sizeof(block));

		sleep(1);
	}

	kcapi_cipher_destroy(kcapi);
}
