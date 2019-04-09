/*
 * A shared library that logs allocations and frees like mtrace() (see
 * man 3 mtrace for details) but works with multi-threaded applications
 * unlike mtrace().  Losely based on
 * https://elinux.org/images/b/b5/Elc2013_Kobayashi.pdf
 *
 * Generates dumps into given locations with sequential numbered dump
 * files with PID in them.
 *
 * There is an mmleak.py script that shrinks the dump files by removing
 * matching allocations and frees. See README.rst for more details.
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>
#include <errno.h>

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

static void * (*mallocp)(size_t);
static void * (*callocp)(size_t, size_t);
static void * (*reallocp)(void *, size_t);
static int    (*posix_memalignp)(void **, size_t, size_t);
static void * (*aligned_allocp)(size_t, size_t);
static void   (*freep)(void *);

static char *mmleak_dir;
static char logfile[1024];

static void __attribute__((constructor)) init(void)
{
	mallocp = (void *(*)(size_t))dlsym(RTLD_NEXT, "malloc");
	callocp = (void *(*)(size_t, size_t)) dlsym (RTLD_NEXT, "calloc");
	reallocp = (void *(*)(void *, size_t))dlsym(RTLD_NEXT, "realloc");
	posix_memalignp = (int (*)(void **, size_t, size_t))
				dlsym(RTLD_NEXT, "posix_memalign");
	aligned_allocp = (void *(*)(size_t, size_t))
				dlsym(RTLD_NEXT, "aligned_alloc");
	freep = (void (*)(void *))dlsym(RTLD_NEXT, "free");

	mmleak_dir = getenv("MMLEAK_DIR");
	if (mmleak_dir == NULL)
		mmleak_dir = "/tmp";
	snprintf(logfile, sizeof(logfile),
		 "%s/mmleak.out", mmleak_dir);
}

#define OP_ALLOC 1
#define OP_FREE  2

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
	static const int64_t max_recs = 100 * 1024 * 1024;
	static int64_t nrecs = 0; /* current record number in the file */
	static int file_num = 0; /* current file numebr */
	static pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
	char fname[1024];
	int c;

	if (atomic_inc_int64_t(&nrecs) % max_recs == 1) {
		PTHREAD_RWLOCK_WRLOCK(&lock);
		if (logfp) {
			fclose(logfp);
			snprintf(fname, sizeof(fname), "%s/mmleak.%d.%d.out",
				 mmleak_dir, getpid(), file_num);
			file_num++;
			if (rename(logfile, fname)) {
				syslog(LOG_DAEMON|LOG_ERR,
				       "rename of %s to %s failed, errno:%d\n",
				       logfile, fname, errno);
			}
		}

		logfp = fopen(logfile, "w");
		if (logfp == NULL) {
			syslog(LOG_DAEMON|LOG_ERR,
			       "open of logfile %s failed, errno:%d\n",
			       logfile, errno);
		}

		snprintf(fname, sizeof(fname),
			 "%s/mmleak.%d.maps", mmleak_dir, getpid());
		if (access(fname, F_OK) == -1) {
			FILE *inf, *outf;

			outf = fopen(fname, "w");
			if (outf == NULL) {
				syslog(LOG_DAEMON|LOG_ERR,
				       "open of %s failed, errno:%d",
				       fname, errno);	
			}

			snprintf(fname, sizeof(fname),
				 "/proc/%d/maps", getpid());
			inf = fopen(fname, "r");
			if (inf == NULL) {
				syslog(LOG_DAEMON|LOG_ERR,
				       "open of %s failed, errno:%d",
				       fname, errno);	
			}

			if (inf && outf) {
				while ((c = fgetc(inf)) != EOF)
					fputc(c, outf);
			}
			if (inf != NULL)
				fclose(inf);
			if (outf != NULL)
				fclose(outf);
		}
		PTHREAD_RWLOCK_UNLOCK(&lock);
	}

	/* If multiple threads call this function at the same time for
	 * the first time, logfile may not have been opened! Unlikely to
	 * happen though!  Will happens after a failure like ENOSPC as
	 * well!
	 */
	if (logfp == NULL)
		return;

	/* fprintf is thread safe, so no need for any lock.  This shared
	 * lock is needed here to avoid threads writing to a closed logfp!
	 */
	PTHREAD_RWLOCK_RDLOCK(&lock);
	switch (op) {
	case OP_ALLOC:
		fprintf(logfp, "%p %p %zu\n", ptr, caller, len);
		break;
	case OP_FREE:
		fprintf(logfp, "%p %p\n", ptr, caller);
		break;
	default:
		abort();
	}
	PTHREAD_RWLOCK_UNLOCK(&lock);
}

/* For allocations that are needed before we get function pointers */
static char my_buffer[1024 * 1024] __attribute__((aligned(8)));
static void *my_malloc(size_t len)
{
	static char *next_alloc = my_buffer;
	void *ret;

	/* mallocs should be on 8 byte boundary */
	len = ((len+7)/8) * 8;
	ret = (void *)next_alloc;
	next_alloc += len;

	if (next_alloc > my_buffer + sizeof(my_buffer)) {
		abort();
	}

	return ret;
}

static void *my_calloc(size_t n, size_t len)
{
	void *ret;

	ret = my_malloc(n * len);
	memset(ret, 0, n * len);
	return ret;
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
	Log(OP_ALLOC, ret, caller, len);
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
	Log(OP_ALLOC, ret, caller, n * len);
	no_hook = 0;

	return ret;
}

void *realloc(void *old, size_t len)
{
	void *ret;
	void *caller;

	if (no_hook)
		return (*reallocp)(old, len);

	no_hook = 1;
	caller = RETURN_ADDRESS(0);
	if (old != NULL)
		Log(OP_FREE, old, caller, 0);
	ret = (*reallocp)(old, len);
	Log(OP_ALLOC, ret, caller, len);
	no_hook = 0;

	return ret;
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
	int ret;
	void *caller;

	if (no_hook)
		return (*posix_memalignp)(memptr, alignment, size);

	no_hook = 1;
	caller = RETURN_ADDRESS(0);
	ret = (*posix_memalignp)(memptr, alignment, size);
	if (ret == 0)
		Log(OP_ALLOC, *memptr, caller, size);
	no_hook = 0;

	return ret;
}

void *aligned_alloc(size_t alignment, size_t size)
{
	void *ret;
	void *caller;

	if (no_hook)
		return (*aligned_allocp)(alignment, size);

	no_hook = 1;
	caller = RETURN_ADDRESS(0);
	ret = (*aligned_allocp)(alignment, size);
	Log(OP_ALLOC, ret, caller, size);
	no_hook = 0;

	return ret;
}

/* Check if the given ptr falls into my_buffer memory */
#define my_buffer(ptr) ((ptr) >= (void *)my_buffer \
		&& (ptr) < (void *)(my_buffer + sizeof(my_buffer)))
void free(void *ptr)
{
	void *caller;

	if (ptr == NULL)
		return;

	if (my_buffer(ptr)) {
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

char *strdup(const char *s)
{
	void *ret;
	void *caller;
	size_t size;
	
	no_hook = 1;
	size = strlen(s) + 1;
	caller = RETURN_ADDRESS(0);
	ret = (*mallocp)(size);
	Log(OP_ALLOC, ret, caller, size);
	memcpy(ret, s, size);
	no_hook = 0;

	return ret;
}

char *strndup(const char *s, size_t n)
{
	void *ret;
	void *caller;
	size_t size;
	
	no_hook = 1;
	size = strnlen(s, n) + 1;
	caller = RETURN_ADDRESS(0);
	ret = (*mallocp)(size);
	Log(OP_ALLOC, ret, caller, size);
	memcpy(ret, s, size);
	no_hook = 0;

	return ret;
}
