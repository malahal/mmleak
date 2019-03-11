mmleak.so: mmleak.c
	cc -Wall -fPIC -shared -o mmleak.so mmleak.c -ldl
