mmleak.so: mmleak.c
	cc -Wall -ggdb -fPIC -shared -o mmleak.so mmleak.c -ldl -lpthread
