/*
 * Based on https://elinux.org/images/b/b5/Elc2013_Kobayashi.pdf
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>

/* GCC version 40700 supports atomic functions. Check compiler
 * version and #error if needed, later
 */
static inline int64_t atomic_inc_int64_t(int64_t *var)
{
	return __atomic_add_fetch(var, 1, __ATOMIC_SEQ_CST);
}
static inline int64_t atomic_dec_int64_t(int64_t *var)
{
	return __atomic_sub_fetch(var, 1, __ATOMIC_SEQ_CST);
}

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

#define OP_MALLOC  1
#define OP_CALLOC  2
#define OP_REALLOC 3
#define OP_ALIGN   4
#define OP_FREE    5

#define PTHREAD_RWLOCK_WRLOCK(x) \
	do { \
		if (pthread_rwlock_wrlock(x)) \
			abort(); \
	} while (0)
#define PTHREAD_RWLOCK_RDLOCK(x) \
	do { \
		if (pthread_rwlock_rdlock(x)) \
			abort(); \
	} while (0)
#define PTHREAD_RWLOCK_UNLOCK(x) \
	do { \
		if (pthread_rwlock_unlock(x)) \
			abort(); \
	} while (0)

static void Log(int op, void *ptr, void *caller, size_t len)
{
	static FILE *logfp = NULL;
	static const int64_t max_recs = 100 * 1024 * 1024; /* TODO: from env */
	static int64_t nrecs = 0; /* current record number in the file */
	static int file_num = 0; /* current file numebr */
	static pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
	char filename[1024]; /* PATH_MAX ? */

	if (atomic_inc_int64_t(&nrecs) % max_recs == 1) {
		PTHREAD_RWLOCK_WRLOCK(&lock);
		if (logfp)
			fclose(logfp);
		snprintf(filename, sizeof(filename),
			 "/tmp/mmleak.%d.%d.out", getpid(), file_num);
		logfp = fopen(filename, "a");
		file_num++;
		PTHREAD_RWLOCK_UNLOCK(&lock);
	}

	/* fprintf is thread safe, so no need for any lock.  This shared
	 * lock is needed to avoid threads writing to a closed logfp
	 *
	 * logfp shouldn't be NULL here unless multiple threads call us
	 * at the very first time. We could just check and go back to
	 * the beginning of this function, if so. Since that is
	 * unlikely, we are not doing it.
	 */
	PTHREAD_RWLOCK_RDLOCK(&lock);
	switch (op) {
	case OP_FREE:
		fprintf(logfp, "%p %p\n", ptr, caller);
		break;
	case OP_MALLOC:
	case OP_CALLOC:
		fprintf(logfp, "%p %p %zu\n", ptr, caller, len);
		break;
	default:
		fprintf(logfp, "bogus op_code:%d", op);
	}
	PTHREAD_RWLOCK_UNLOCK(&lock);
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

void *my_malloc(size_t len)
{
	return my_calloc(1, len);
}

void my_free(void *ptr)
{
	return;
}

static __thread int no_hook;
void *malloc (size_t len)
{
	void *ret;
	void *caller;

	if (mallocp == NULL)
		return my_malloc(len);

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

#define my_buffer(ptr) ((ptr) >= (void *)my_buffer \
		&& (ptr) < (void *)(my_buffer + sizeof(my_buffer)))
void free(void *ptr)
{
	void *caller;

	if (ptr == NULL)
		return;

	/* Don't free our static buffer */
	if (my_buffer(ptr)) {
		my_free(ptr);
		return;
	}

	if (no_hook) {
		(*freep)(ptr);
		return;
	}

	no_hook = 1;
	caller = RETURN_ADDRESS(0);
	Log(OP_FREE, ptr, caller, 0);
	(*freep)(ptr);
	no_hook = 0;
}
