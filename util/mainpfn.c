#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

struct pageinfo {
	uint64_t pfn : 54;
	unsigned int soft_dirty : 1;
	unsigned int file_page : 1;
	unsigned int swapped : 1;
	unsigned int present : 1;
};

void
pagemap_get_entry(struct pageinfo *entry, int fd, uintptr_t vaddr)
{
	uint64_t data;
	size_t offset;

	offset = (vaddr / sysconf(_SC_PAGE_SIZE)) * 8;
	if (pread(fd, (void *) &data, 8, offset) != 8)
		err(1, "pread");

	entry->pfn = data & ((1ULL << 54) - 1);
	entry->soft_dirty = (data >> 54) & 1;
	entry->file_page = (data >> 61) & 1;
	entry->swapped = (data >> 62) & 1;
	entry->present = (data >> 63) & 1;
}

int
main(int argc, const char **argv)
{
	char filepath[256];
	struct pageinfo info;
	pid_t pid;
	int fd;

	pid = getpid();
	snprintf(filepath, sizeof(filepath), "/proc/%u/pagemap", pid);

	fd = open(filepath, O_RDONLY);
	if (!fd) err(1, "open");

	pagemap_get_entry(&info, fd, (uintptr_t) main);
	printf("PFN: %08lx\n", info.pfn);

	close(fd);
}
