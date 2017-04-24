gen : 1Generator.c
	gcc -Wall -o gen 1Generator.c
	gcc -Wall -o clasT 2ClassifierTREE.c
	gcc -Wall -o fab 3FabricBANYAN.c -lm
	gcc -Wall -o schedR 4SchedulerRR.c
	gcc -Wall -o analys 5Analyser.c

clean :
	rm gen clasT fab schedR analys