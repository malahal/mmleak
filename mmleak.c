#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

#define RETURN_ADDRESS(nr) \
	__builtin_extract_return_addr(__builtin_return_address (nr))

void * (*mallocp)(size_t);
void * (*callocp)(size_t, size_t);
void * (*reallocp)(void *, size_t);
void * (*memalignp)(size_t, size_t);
void   (*freep)(void *);

static void __attribute__((constructor)) init(void)
{
	mallocp = (void *(*) (size_t)) dlsym (RTLD_NEXT, "malloc");
	reallocp = (void *(*) (void *, size_t)) dlsym (RTLD_NEXT, "realloc");
	memalignp = (void *(*)(size_t, size_t)) dlsym (RTLD_NEXT, "memalign");
	freep = (void (*) (void *)) dlsym (RTLD_NEXT, "free");
	callocp = (void *(*) (size_t, size_t)) dlsym (RTLD_NEXT, "calloc");
}

#define OP_MALLOC 1
#define OP_FREE   2

static void Log(int op, void *ptr, void *caller, size_t len)
{
	static FILE *logfp;

	if (!logfp) {
		logfp = fopen("/tmp/mmleak.txt", "w");
	}

	if (op == OP_FREE)
		fprintf(logfp, "%p %p\n", ptr, caller);
	else
		fprintf(logfp, "%p %p %zu\n", ptr, caller, len);
}

/* For allocation that need before DL open stuff?? */
static char my_buffer[16 * 1024 * 1024];
void *my_calloc(size_t n, size_t len)
{
	static char *free_ptr = my_buffer;
	char *ret;

	ret = free_ptr;
	free_ptr = free_ptr + n * len;

	if (free_ptr > my_buffer + sizeof(my_buffer)) {
		abort();
	}

	/* Buffer is already initialized */
	return ret;
}

static __thread int no_hook;
void *malloc (size_t len)
{
	void *ret;
	void *caller;

	if (mallocp == NULL)
		return my_calloc(1, len);

	if (no_hook)
		return (*mallocp)(len);

	no_hook = 1;
	caller = RETURN_ADDRESS(0);
	ret = (*mallocp)(len);
	Log(OP_MALLOC, ret, caller, len);
	no_hook = 0;

	return ret;
}

void *calloc(size_t n, size_t len)
{
	void *ret;
	void *caller;

	if (callocp == NULL)
		return my_calloc(n, len);

	if (no_hook)
		return (*callocp)(n, len);

	no_hook = 1;
	caller = RETURN_ADDRESS(0);
	ret = (*callocp)(n, len);
	Log(OP_MALLOC, ret, caller, n * len);
	no_hook = 0;

	return ret;
}

void free(void *ptr)
{
	void *caller;

	if (ptr == NULL)
		return;

	/* Don't free our static buffer */
	if (ptr >= (void *)my_buffer
			&& ptr < (void *)(my_buffer + sizeof(my_buffer)))
		return;

	if (no_hook) {
		(*freep)(ptr);
		return;
	}

	no_hook = 1;
	caller = RETURN_ADDRESS(0);
	(*freep)(ptr);
	Log(OP_FREE, ptr, caller, 0);
	no_hook = 0;
}
