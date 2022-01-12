#!/bin/bash
echo -n "Compiling server ... "
cd server
gcc -Wall server.c -o server -lpcap -lpthread
cd ..
echo "Done!"
echo -n "Compiling client ... "
cd client
gcc -Wall client.c -o client `pkg-config --cflags --libs gtk+-2.0 --libs gthread-2.0`
cd ..
echo "Done!"
echo "The executables are in both server and client directory."
