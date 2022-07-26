#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>

int
main(int argc, const char **argv)
{
	uint16_t counts[64];
	size_t i, len;
	int fd;

	fd = open("/proc/cachepc", O_RDONLY);
	len = read(fd, counts, sizeof(counts));
	assert(len == sizeof(counts));

	for (i = 0; i < 64; i++) {
		if (i % 16 == 0 && i)
			printf("\n");
		if (counts[i] > 0)
			printf("\x1b[91m");
		printf("%2i ", i);
		if (counts[i] > 0)
			printf("\x1b[0m");
	}
	printf("\n");
	
	close(fd);
}
