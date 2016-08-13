default: lisod_server

lisod_server: lisod.c main.c state.h
	gcc -lssl -lcrypto -o lisod lisod.c ssl.c log.c daemonize.c main.c

clean:
	rm lisod
	rm log.txt

submit:
	git add .;
	git commit -m "${CM}"
	git tag -a final -m "forcing checkpoint" --force
