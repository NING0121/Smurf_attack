attack:normal_dos.o fakeip_dos.o ddos.o smurf.o
	gcc  normal_dos.o fakeip_dos.o ddos.o smurf.o -o attack -lpthread
normal_dos.o:normal_dos.c
	gcc -c normal_dos.c -lpthread
fakeip_dos.o:fakeip_dos.c
	gcc -c fakeip_dos.c -lpthread
ddos.o:ddos.c
	gcc -c ddos.c -lpthread
smurf.o:smurf.c
	gcc -c smurf.c
.PHONY:clean
clean:
	-rm -rf *.o