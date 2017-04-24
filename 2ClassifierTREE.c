/* Daniel Paul Iuliano
z3101121
diuliano@gmail.com
Thesis Topic University of New South Wales
Supervisor: Tim Moors
The PC Switch

Packet Classifier
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>		// socket() & bind()
#include <errno.h>			// for DieWithError() function
#include <arpa/inet.h>		// sockaddr_in
#include <time.h>			// for random timer

#define INPUT_PORT 50000
#define OUTPUT_PORT 50001
#define LOCAL_ADDRESS "127.0.0.1"
#define MAX_MSG_LEN 200

// Declare treeArray linklist for creating routing tree.
typedef struct treeArray treeArray;
struct treeArray {
	int port;
	char field[9];
	treeArray *link[256];
};
treeArray *root = NULL;

typedef struct packet packet; // packet struct
struct packet {
	char ip_dest[4][9];
	char ip_source[4][9];
	short int dataLength;
	char data[100];
	int frameCheck;
	int fromPort;
	int toPort;
	int sequenceNum;
	int portSequenceNum;
	int timer;
};

// Packet classifier functions
int search(char ip_addr[4][9]);
void display_database(treeArray *root, int i);
void add_address(char ip_addr[4][9], int prefix, int assdata_port);
void treeTable();

// Misc functions
void dec2bin(int decimal, char *binary);
int bin2dec(char *binary);
void DieWithError(char *errorMessage);
void createIP(int i1, int i2, int i3, int i4, char ip_addr[4][9]);

int main() {
	struct sockaddr_in genOUT_addr;		// client info (generator) variable, data given when received message
	struct sockaddr_in clasIN_addr;		// struct for incoming packets
	struct sockaddr_in clasOUT_addr;	// struct for outgoing packets
	unsigned int genAddrLen;			// int to store length of client address (generator) data when received
	packet recvPacket;					// packet struct that will be received/sent
	int sockIN, sockOUT, recvMsgLen, port, sequence[8], n;	// sequence counts packets sent to each port
	int dtxt[4], prefixtxt, porttxt;	// dtxt holds ip address from txt file, prefix and port from txt also
	char ip_dest_txt[4][9];				// stores ip address from txt
	FILE *file;

	//----------------Network code----------------
	// Open socket
	if((sockIN = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		DieWithError("socket() failed");
	if((sockOUT = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		DieWithError("socket() failed");

	// Construct local address structure
	bzero((char *)&clasIN_addr, sizeof(clasIN_addr));	// zeroes out struct before data copied
    clasIN_addr.sin_family = AF_INET;					// specifies Address Family
    clasIN_addr.sin_addr.s_addr = htonl(INADDR_ANY);	// accept from any network interface
    clasIN_addr.sin_port = htons(INPUT_PORT);			// Using port 50000
    // Construct outgoing address structure
	bzero((char *)&clasOUT_addr,sizeof(clasOUT_addr));			// zeroes out struct before data copied
    clasOUT_addr.sin_family = AF_INET;							// specifies Address Family
    clasOUT_addr.sin_addr.s_addr = inet_addr(LOCAL_ADDRESS);	// Connect to local address
    clasOUT_addr.sin_port = htons(OUTPUT_PORT);					// output port 50001
	
    // Binding above data (address/port/etc) to socket descriptor sock for port 50000
    if((bind(sockIN, (struct sockaddr *)&clasIN_addr, sizeof(clasIN_addr))) < 0)
    	DieWithError("bind() failed");
    //--------------End Network code--------------
    
    treeTable();		// setup random tree table
	
	file = fopen("clasEntry.txt", "r");	// open txt file to get pretermined tree entry
	if(file != NULL) {
		fscanf(file, "Destination:%i.%i.%i.%i Prefix:%i Port:%i", &dtxt[0], &dtxt[1], &dtxt[2], &dtxt[3], &prefixtxt, &porttxt);
		fclose(file);
		printf("Destination:%i.%i.%i.%i Prefix:%i Port:%i\n", dtxt[0], dtxt[1], dtxt[2], dtxt[3], prefixtxt, porttxt);
		createIP(dtxt[0], dtxt[1], dtxt[2], dtxt[3], ip_dest_txt);	// creates ip address from numbers from txt file
		add_address(ip_dest_txt, prefixtxt, porttxt);				// add txt file address to table
	}
	
	srand (time(NULL));			// initialize random seed
		
	for(n=0;n<8;n++)			// zero sequence array
		sequence[n]=0;
	
	display_database(root, 0);	// Display address database (optional)
    	
	while(1) {
		if((recvMsgLen = recvfrom(sockIN, &recvPacket, MAX_MSG_LEN, 0, (struct sockaddr *) &genOUT_addr, &genAddrLen)) < 0)
    		DieWithError("recvfrom() failed");
						
		// Search for address
		port = search(recvPacket.ip_dest);	// returns port that classifer says output should be to

		printf("IP Dest: %i.%i.%i.%i ", bin2dec(recvPacket.ip_dest[0]), bin2dec(recvPacket.ip_dest[1]), bin2dec(recvPacket.ip_dest[2]), bin2dec(recvPacket.ip_dest[3]));
		printf("packet %i will be directed to port %i\n", recvPacket.sequenceNum, port);
		
		recvPacket.toPort = port;					// from search function
		sequence[port]++;							// increments sequence number array corresponding to array it is being sent too
		recvPacket.portSequenceNum = sequence[port];// changes sequence number to it's port sequence
							
		// send packet to fabric
		if(sendto(sockOUT, &recvPacket, MAX_MSG_LEN, 0, (struct sockaddr *)&clasOUT_addr, sizeof(clasOUT_addr)) != MAX_MSG_LEN)
			DieWithError("sendto() failed");
	}
	
	return 0;
}

/*
PACKET CLASSIFIER FUNCTIONS
*/

// Function to search tree-array
// Search first tier for number 1 match, if no match, print root node
// if match, search 2nd tier for number 2 match, and so on
int search(char ip_addr[4][9]) {
	// i is number of tiers searched to, where 0 is root and 4 is 4th number of IP, count keeps track of how many steps in search
	int n=0, i=0, count=0;
	treeArray *current = NULL;
	treeArray *final = NULL;	

	current = root;
		
	while(final == NULL) {
		n=0;
		count++;
		if(current->link[0] == NULL) {
			final = current;
			break;
		}
		// this loop searches all the branches in that node for fields that
		// match the next number of the destination address
		while(strcmp(current->link[n]->field, ip_addr[i]) != 0) {
			n++;
			count++;
			if(current->link[n] == NULL) {
				final = current;
				break;
			}
		}
		current = current->link[n];
		i++;
	}
	printf("%i steps through tree, ", count);

	return final->port;
}

// recursively patrol tree and print every field
void display_database(treeArray *base, int i) {
	int n=0, j;
	
	for(j=i;j>0;j--)	// print amount of tabs depending on what tier
		printf("	");
	printf("%i -> Port: %i\n", bin2dec(base->field), base->port);
	i++;
	while(base->link[n] != NULL) {
		display_database(base->link[n], i);
		n++;
	}
}

// Function to add entry to tree
void add_address(char ip_addr[4][9], int prefix, int assdata_port) {
	int n=0, i=1;
	treeArray *current = root;
	treeArray *prev = NULL;

	// i is the tier of the table being searched
	// i.e. ip1 is tier 1, ip2 is tier 2, etc
	while(i<=prefix) {
		while(n<256) {
			if(current->link[n] == NULL) {
				prev = current;
				if((current = (treeArray *)malloc(sizeof(treeArray))) != NULL){
					// copies current tier of IP address to current field
					strcpy(current->field, ip_addr[i-1]);
					prev->link[n] = current;
					// if at prefix tier, added address correctly
					if(i==prefix) {
						current->port = assdata_port;
						return;
					} else { // otherwise keep going
						current->port = prev->port;
						i++;
						break;
					}
				}else{
					printf("Out of Memory");
					exit(0);
				}
			} else {
				if(strcmp(current->link[n]->field, ip_addr[i-1]) == 0) {
					// found address. If at target prefix tier, address already exists
					if(i==prefix) {
						printf("Address already exists\n");
						return;
					} else { // if not, keep going
						i++;
						current = current->link[n];
						break;
					}
				} else {
					// haven't found yet, search next link on that tier
					n++;
				}
			}
		}
		n=0;
	}
}

// create random tree table
void treeTable() {
	// variables t1, t2, t3, t4 determine how many random entries per branch at the corresponding tier are added
	// t1=50 means 0 to 50 branches added at tier 1
	int root1Branch, root2Branch, root3Branch, root4Branch, n1, n2, n3, n4, tempField, t1=50, t2=5, t3=2, t4=2;
	char tempBin[9];
	treeArray *prev = NULL;
	treeArray *prev2 = NULL;
	treeArray *prev3 = NULL;
	treeArray *current = NULL;
		
	if((root = (treeArray *)malloc(sizeof(treeArray))) != NULL){	// initialise root of tree to port 0 default gateway
		root->port = 0;
		strcpy(root->field, "00000000");
	} else {
		printf("Out of Memory");
		exit(0);
	}
	
	root1Branch = rand() % t1;		// randomise for amount of branches from root
	for(n1=0;n1<root1Branch;n1++) {	// create that number and attach to root
		if((current = (treeArray *)malloc(sizeof(treeArray))) != NULL){
			current->port = rand() % 8;
			tempField = rand() % 256;
			dec2bin(tempField, tempBin);
			strcpy(current->field, tempBin);
			root -> link[n1] = current;
			prev = current;
		
			root2Branch = rand() % t2;		// randomise for amount of branches from tier 1
			for(n2=0;n2<root2Branch;n2++) {	// create that number and attach to tier 1 branch it spawned off
				if((current = (treeArray *)malloc(sizeof(treeArray))) != NULL){
					current->port = rand() % 8;
					tempField = rand() % 256;
					dec2bin(tempField, tempBin);
					strcpy(current->field, tempBin);
					prev -> link[n2] = current;
					prev2 = current;
					
					root3Branch = rand() % t3;		// randomise for amount of branches from tier 2
					for(n3=0;n3<root3Branch;n3++) {	// create that number and attach to tier 2 branch it spawned off
						if((current = (treeArray *)malloc(sizeof(treeArray))) != NULL){
							current->port = rand() % 8;
							tempField = rand() % 256;
							dec2bin(tempField, tempBin);
							strcpy(current->field, tempBin);
							prev2 -> link[n3] = current;
							prev3 = current;
					
							root4Branch = rand() % t4;		// randomise for amount of branches tier 3
							for(n4=0;n4<root4Branch;n4++) {	// create that number and attach to tier 3 branch it spawned off
								if((current = (treeArray *)malloc(sizeof(treeArray))) != NULL){
									current->port = rand() % 8;
									tempField = rand() % 256;
									dec2bin(tempField, tempBin);
									strcpy(current->field, tempBin);
									prev3 -> link[n4] = current;
								} else {
									printf("Out of Memory");
									exit(0);
								}
							}
						} else {
							printf("Out of Memory");
							exit(0);
						}
					}
				} else {
					printf("Out of Memory");
					exit(0);
				}
			}
		
		} else {
			printf("Out of Memory");
			exit(0);
		}
	}
}

/*
MISC FUNCTIONS
*/

// dec2bin conversion from decimal to binary used&edited from: http://www.daniweb.com/code/snippet87.html
void dec2bin(int decimal, char *binary) {
	int k = 0, n, i, remain;
	char temp[8];

	for(n=0;n<8;n++) {			// zero the binary string
		binary[n] = '0';
	}
	binary[n] = '\0';
	
	do {
		remain = decimal % 2;	// whittle down the decimal number
		decimal = decimal / 2;
		temp[k] = remain + '0';	// converts digit 0 or 1 to character '0' or '1'
		k++;
	} while (decimal > 0);
	
	n=7;
	for(i=0;i<k;i++) {		// reverse the spelling
		binary[n] = temp[i];
		n--;
	}
}

// Convert binary string into decimal
int bin2dec(char *binary) {
	int n=strlen(binary)-1, i=1, decimal=0;
	
	while(n>=0) {
		if(binary[n] == '1')
			decimal = decimal+i;
		n--;
		i = i*2;
	}
	
	return decimal;
}

// Merge 4 numbers into multi-dimensional array
void createIP(int i1, int i2, int i3, int i4, char ip_addr[4][9]) {
	int n,i;
	
	for(i=0;i<4;i++) {	// Zero the ip address
		for(n=0;n<8;n++) {
			ip_addr[i][n] = '0';
		}
	}
	// Convert each number of the IP address to binary conversion (8bits)
	dec2bin(i1, ip_addr[0]);
	ip_addr[0][8] = '\0';
	dec2bin(i2, ip_addr[1]);
	ip_addr[1][8] = '\0';
	dec2bin(i3, ip_addr[2]);
	ip_addr[2][8] = '\0';
	dec2bin(i4, ip_addr[3]);
	ip_addr[3][8] = '\0';
}

void DieWithError(char *errorMessage)
{
    perror(errorMessage);
    exit(1);
}
