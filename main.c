#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<math.h>
#include<time.h>

//my libraries
#include "blake2blib.h"
#include "argon2_core.h"
#include "common.h"

//default parameters
#define TCOST_DEF 3
#define LOG_M_COST_DEF 12 //2^12 = 4 MiB = 4096 Kibibytes
#define LANES_DEF 1
#define TAGLEN_DEF 32
#define MAX_PASS_LEN 128

//print the usage
void usage(char *argon2) {
    printf("Usage: %s [-P password] [-S salt] [-i|-d|-id] [-t iterations] [-m memory] "
           "[-p parallelism] [-T tag length] [-K secret key] [-X associated Data]\n",
           argon2);
    printf("Mandatory parameters:\n");
	printf("\t-P ...\t\tThe password to use, may have any length from 0 to 2**32 - 1 bytes\n");
    printf("\t-S ...\t\tThe salt to use, at least 8 characters\n");
	printf("Non mandatory parameters:\n");
    printf("\t-i\t\tUse Argon2i (this is the default)\n");
    printf("\t-d\t\tUse Argon2d instead of Argon2i\n");
    printf("\t-id\t\tUse Argon2id instead of Argon2i\n");
    printf("\t-t N\t\tSets the number of iterations to N (default = %d)\n", TCOST_DEF);
    printf("\t-m N\t\tSets the memory usage of 2^N KiB (default %d)\n", LOG_M_COST_DEF);
    printf("\t-p N\t\tSets parallelism to N threads (default %d)\n", LANES_DEF);
    printf("\t-T N\t\tSets tag output length equal to N bytes (default %d)\n", TAGLEN_DEF);
    printf("\t-K ...\t\tThe secret key to use\n");
    printf("\t-X ...\t\tThe associated data to use\n");
}

//associate a type with its string
char* type2string(int type) {
	
	switch(type) {
		case 0 : 
			return "Argon2d";
		case 1 : 
			return "Argon2i";
		case 2 : 
			return "Argon2id";
		default : 
			return "Argon2i";
	}
	return "no way!";
}

//run argon2
int run(uint32_t tag_len, char *psw, char *salt, uint32_t t_cost, uint32_t m_cost, uint32_t lanes, int type, char *K, char *X) {
	
	//variables needed to compute how much time is required to run argon2
	clock_t start_time, stop_time;
	
	//start recording
	start_time = clock();
	
	//declaration of ctx
	argon2_ctx ctx;
	
	//initialize all the fields of ctx
	
	//primary (mandatory) inputs
    ctx.psw 		= (uint8_t*) psw;			//password
    ctx.length_psw 	= (uint32_t) strlen(psw);	//password length
    ctx.salt		= (uint8_t*) salt;			//salt
    ctx.length_salt	= (uint32_t) strlen(salt);	//salt length
	
	//non mandatory inputs
	if(K != NULL) {
		ctx.K = (uint8_t*) K;					//secret key
		ctx.length_K = (uint32_t) strlen(K);    //secret key length
	} else {                                    
		ctx.K = NULL;                           
		ctx.length_K = 0;                       
	}
	if(X != NULL) {
		ctx.X = (uint8_t*) X;					//associated data
		ctx.length_X = (uint32_t) strlen(X);    //associated data length
	} else {
		ctx.X = NULL; 
		ctx.length_X = 0;
	}
	
	//secondary inputs
    ctx.t 			= t_cost;				//number of iterations
    ctx.m			= m_cost;				//2^m is the number of KiB used
    ctx.p 			= lanes;				//number of lanes, equal to the degree of parallelism
    ctx.v 			= 0x13;					//version 19
	ctx.y 			= type;					//Argon2i or Argon2d or Argon2id
	ctx.T			= (uint32_t) tag_len;	//number of bytes of the final tag
	
	//other inputs
	ctx.m_prime 		= 4 * ctx.p * ((uint32_t)floor(ctx.m / (4 * ctx.p)));   //number of blocks
	ctx.q 				= ctx.m_prime/ctx.p;									//number of columns
	ctx.segment_length 	= (uint32_t) ctx.q/4;									//length of a segment
	
	
	//allocate memory for the tag
    uint8_t* tag = (uint8_t*) calloc(tag_len, sizeof(uint8_t));
    if (tag == NULL) {
        printf("could not allocate memory for tag\n");
		return -1;
    }
	
	//"core" function
    tag = getTag_argon2(&ctx);

	//stop time here
	stop_time = clock();
	
	//print password
	printf("Password[%lu]:\t\t", ctx.length_psw);
	for(uint32_t i=0; i<ctx.length_psw; i++) {
		printf("%02x ", ctx.psw[i]);
	}
	printf("\n");
	
	//print salt
	printf("Salt[%lu]:\t\t", ctx.length_salt);
	for(uint32_t i=0; i<ctx.length_salt; i++) {
		printf("%02x ", ctx.salt[i]);
	}
	printf("\n");
	
	//print K
	if(K != NULL) {
		printf("Secret[%lu]:\t\t", ctx.length_K);
		for(uint32_t i=0; i<ctx.length_K; i++) {
			printf("%02x ", ctx.K[i]);
		}
		printf("\n");
	} else {
		printf("Secret[0]:\n");
	}
	
	//print X
	if(X != NULL) {
		printf("Associated Data[%lu]:\t", ctx.length_X);
		for(uint32_t i=0; i<ctx.length_X; i++) {
			printf("%02x ", ctx.X[i]);
		}
		printf("\n");
	} else {
		printf("Associated Data[0]:\n");
	}
	printf("\n");
	
	//print the pre-hashing digest
	printf("Pre-hashing digest:\t");
	for(int i=0; i<64; i++) {
		if(i%8 == 0 && i!=0) {printf("\n\t\t\t");}
		printf("%02x ", ctx.H_0[i]);
	}
	printf("\n\n");
	
	//print tag
	printf("Tag:\t");
	for(uint32_t i=0; i<ctx.T; i++) {
		printf("%02x", tag[i]);
	}
	printf("\n\n");
	
	//print how much time has been requested
    printf("Elapsed time:\t%2.3f seconds\n", ((double)stop_time - start_time) / (CLOCKS_PER_SEC));
	
	//free memory
	free(tag);
	
	return 0;	
};

//main function
int main(int argc, char *argv[]) {
	
	//setting default values
	uint32_t t_cost = TCOST_DEF;
	uint32_t m_cost = (uint32_t) pow(2, LOG_M_COST_DEF);
	uint32_t lanes = LANES_DEF;
	uint32_t tag_len = TAGLEN_DEF;
	
	//Argon2i is the default type
    int type = ARGON2I; 
	int type_specified = 0;
	
	//mandatory parameters to be used
    char *pwd = NULL;
	char *salt = NULL;
	
	//other parameters non mandatory, default NULL
    char *K = NULL;
	char *X = NULL;

	//Here is the handling of input taken from file. The input have to be specified in the file named inputFile.txt. 
	//The user must indicate the input value leaving one space after every label.
	if(argc == 2){
		if(strcmp(argv[1], "-IF") != 0){
			printf("Remember to specify the input mode: insert inputs from command line or specify the option -IF to read inputs from file");
		}
		else{
			int i = 0;
		    char lines[30][BUFSIZ];
		    FILE *fp = fopen("inputFile.txt", "r");

		    if (fp == 0)
		    {
		        fprintf(stderr, "failed to open input.txt\n");
		        exit(1);
		    }
		    while (fgets(lines[i], sizeof(lines[0]), fp) != NULL)
		    {
		        lines[i][strlen(lines[i])-2
		        	] = '\0';
		        i = i + 1;
		    }
		    fclose(fp);
		    
		    for(int j=0; j<i; j++){
		        if(strncmp (lines[j],"PSW",3) == 0){
		            //save the password specified in the input file
		            pwd = lines[j]+5;
		            if (strlen(pwd) < MIN_PWD_LENGTH || strlen(pwd) > MAX_PWD_LENGTH) {
		                printf("non valid input for password\n");
		                return -1;
		            }
		        }
		        if(strncmp (lines[j],"SALT",4) == 0){
		            //save the salt specified in the input file
		            salt = lines[j] + 6;
		            if (strlen(salt) < MIN_SALT_LENGTH || strlen(salt) > MAX_SALT_LENGTH) {
		                printf("non valid input for salt\n");
		                return -1;
		            }
		        }
		        if(strncmp (lines[j],"K",1) == 0){
		            //save the K value specified in the input file
		            K = lines[j] + 3;
		            if (strlen(K) < MIN_SK_LENGTH || strlen(K) > MAX_SK_LENGTH) {
		                printf("non valid input for K\n");
		                return -1;
		            }
		        }
		        if(strncmp (lines[j],"X",1) == 0){
		            //save the X value specified in the input file
		            X = lines[j] + 3;
		            if (strlen(X) < MIN_AD_LENGTH || strlen(X) > MAX_AD_LENGTH) {
		                printf("non valid input for X\n");
		                return -1;
		            }
		        }
		        if(strncmp (lines[j],"m",1) == 0){
		            m_cost = (uint32_t) pow(2,strtoul(lines[j] + 3, NULL, 10));
		            if (m_cost < MIN_MEMORY || m_cost > MAX_MEMORY) {
		                printf("out of range input for memory cost m\n");
		                return -1;
		            }
		        }
		        if((strncmp (lines[j],"t",1) == 0) && (strncmp(lines[j],"type",4) !=0)){
		            t_cost = strtoul(lines[j] + 3, NULL, 10);
		            if (t_cost < MIN_ITERATIONS || t_cost > MAX_ITERATIONS) {
		                printf("out of range input for number of iterations t\n");
		                return -1;
		            }
		        }
		        if(strncmp (lines[j],"p",1) == 0){
		            lanes = strtoul(lines[j] + 3, NULL, 10);
		            if (lanes < MIN_LANES || lanes > MAX_LANES) {
		                printf("out of range input for number of lanes i.e. degree of parallelism p\n");
		                return -1;
		            }
		        }

		        if(strncmp (lines[j],"T",1) == 0){
		            tag_len = strtoul(lines[j] + 3, NULL, 10);
		            if (tag_len < MIN_TAG_LEN || tag_len > MAX_TAG_LEN) {
		                printf("out of range input for tag length T\n");
		                return -1;
		            }
		        }
		        if (strncmp( lines[j], "type",4) == 0) {
		            if(strcmp (lines[j] + 6,"ARGON2I")){
		                type = ARGON2I;
		            }
		            else if(strcmp (lines[j] + 6,"ARGON2ID"))
		                type = ARGON2ID;
		            else if(strcmp (lines[j] + 6,"ARGON2D"))
		                type = ARGON2D;
		            else{
		                printf("Invalid specified type\n");
		                return -1;
		            }

		            type_specified++;
		    
		        }
		    }

		}
	}
	
	if(argc != 2){//If the user does not intend to specify input in suitable file and if argc < 5 user is surely wrong, print the usage
	    if (argc < 5) {
			printf("If you choose the command line input mode, remember to insert at least a password and a salt. Here there is the usage:\n");
	        usage(argv[0]);
	        return -1;
	    }
		else{
			//parsing the input from command line
			for (int i = 1; i < argc; i++) {
				const char *a = argv[i];
				unsigned long input = 0;
				if (strcmp(a, "-P") == 0) {
					if (i < argc - 1) {
						i++;
						pwd = argv[i];
						if (strlen(pwd) < MIN_PWD_LENGTH || strlen(pwd) > MAX_PWD_LENGTH) {
							printf("non valid input for password\n");
							return -1;
						}
						continue;
					} else {
						printf("missing -P argument");
						usage(argv[0]);
						return -1;
					}
				} else if (strcmp(a, "-S") == 0) {
					if (i < argc - 1) {
						i++;
						salt = argv[i];
						if (strlen(salt) < MIN_SALT_LENGTH || strlen(salt) > MAX_SALT_LENGTH) {
							printf("non valid input for salt\n");
							return -1;
						}
						continue;
					} else {
						printf("missing -S argument");
						usage(argv[0]);
						return -1;
					}
				} else if (strcmp(a, "-K") == 0) {
					if (i < argc - 1) {
						i++;
						K = argv[i];
						if (strlen(K) < MIN_SK_LENGTH || strlen(K) > MAX_SK_LENGTH) {
							printf("non valid input for K\n");
							usage(argv[0]);
							return -1;
						}
						continue;
					} else {
						printf("missing -K argument");
						usage(argv[0]);
						return -1;
					}
				} else if (strcmp(a, "-X") == 0) {
					if (i < argc - 1) {
						i++;
						X = argv[i];
						if (strlen(X) < MIN_AD_LENGTH || strlen(X) > MAX_AD_LENGTH) {
							printf("non valid input for X\n");
							usage(argv[0]);
							return -1;
						}
						continue;
					} else {
						printf("missing -X argument");
						usage(argv[0]);
						return -1;
					}
				} else if (strcmp(a, "-m") == 0) {
					if (i < argc - 1) {
						i++;
						input = strtoul(argv[i], NULL, 10);
						if (pow(2,input) < MIN_MEMORY || pow(2,input) > MAX_MEMORY) {
							printf("out of range input for memory cost -m\n");
							return -1;
						}
						m_cost = (uint32_t) pow(2,input);
						continue;
					} else {
						printf("missing -m argument");
						usage(argv[0]);
						return -1;
					}
				} else if (strcmp(a, "-t") == 0) {
					if (i < argc - 1) {
						i++;
						input = strtoul(argv[i], NULL, 10);
						if (input < MIN_ITERATIONS || input > MAX_ITERATIONS) {
							printf("out of range input for number of iterations -t\n");
							return -1;
						}
						t_cost = input;
						continue;
					} else {
						printf("missing -t argument");
						usage(argv[0]);
						return -1;
					}
				} else if (strcmp(a, "-p") == 0) {
					if (i < argc - 1) {
						i++;
						input = strtoul(argv[i], NULL, 10);
						if (input < MIN_LANES || input > MAX_LANES) {
							printf("out of range input for number of lanes i.e. degree of parallelism -p\n");
							return -1;
						}
						lanes = input;
						continue;
					} else {
						printf("missing -p argument");
						usage(argv[0]);
						return -1;
					}
				} else if (strcmp(a, "-T") == 0) {
					if (i < argc - 1) {
						i++;
						input = strtoul(argv[i], NULL, 10);
						if (input < MIN_TAG_LEN || input > MAX_TAG_LEN) {
							printf("out of range input for tag length -T\n");
							return -1;
						}
						tag_len = input;
						continue;
					} else {
						printf("missing -T argument");
						usage(argv[0]);
						return -1;
					}
				} else if (strcmp(a, "-i") == 0) {
					type = ARGON2I;
					type_specified++;
				} else if (strcmp(a, "-d") == 0) {
					type = ARGON2D;
					type_specified++;
				} else if (strcmp(a, "-id") == 0) {
					type = ARGON2ID;
					type_specified++;
				} else {
					printf("unknown argument\n");
					usage(argv[0]);
					return -1;
				}
			}
	    }
	}
	
	//control if user has inserted more than 1 type of argon2
    if (type_specified > 1) {
        printf("cannot specify multiple Argon2 types");
		return -1;
    }
	
	//print "intro"
	printf("=====================================================\n");
	printf("%s version number %lu\n",type2string(type), 0x13);
	printf("=====================================================\n");
	
	//print the chosen parameters
	printf("Memory:\t\t%lu KiB\n", m_cost);
	printf("Iterations:\t%lu\n", t_cost);
	printf("Parallelism:\t%lu\n", lanes);
    printf("Tag length:\t%lu bytes\n\n", tag_len);
	
	//check if pwd and salt are null
	if(pwd == NULL || salt == NULL) {
		printf("Something went wrong! password or salt are null\n");
		usage(argv[0]);
		return -1;
	}
	
	//run argon2
    run(tag_len, pwd, salt, t_cost, m_cost, lanes, type, K, X);

    return 0;
}



