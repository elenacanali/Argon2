#ifndef COMMON_H
#define COMMON_H

#include<stdint.h>
#include<stdlib.h>
#include<stdio.h>

/*
 * Argon2 input parameter restrictions
 */

/* Minimum and maximum number of lanes which is equal to the degree of parallelism */
#define MIN_LANES 1
#define MAX_LANES 0xFFFFFF	//2^24 - 1

/* Number of synchronization points between lanes per pass */
#define SYNC_POINTS 4

/* Number of bytes in each block*/
#define BLOCK_SIZE 1024
#define WORDS_IN_BLOCK 128 	//1024/8 = 128

/* Minimum and maximum number of memory blocks (each of BLOCK_SIZE bytes) */
#define MIN_MEMORY 8 			//2 blocks per slice
#define MAX_MEMORY 0xFFFFFFFF	//2^32 - 1 blocks

/* Minimum and maximum digest size in bytes */
#define MIN_TAG_LEN 4
#define MAX_TAG_LEN 0xFFFFFFFF		//2^32 - 1

/* Minimum and maximum number of iterations/passes */
#define MIN_ITERATIONS 1
#define MAX_ITERATIONS 0xFFFFFFFF	//2^32 - 1

/* Minimum and maximum password length in bytes */
#define MIN_PWD_LENGTH 0
#define MAX_PWD_LENGTH 0xFFFFFFFF 	//2^32 - 1

/* Minimum and maximum associated data length in bytes */
#define MIN_AD_LENGTH 0
#define MAX_AD_LENGTH 0xFFFFFFFF	//2^32 - 1 

/* Minimum and maximum salt length in bytes */
#define MIN_SALT_LENGTH 8
#define MAX_SALT_LENGTH 0xFFFFFFFF	//2^32 - 1

/* Minimum and maximum key length in bytes */
#define MIN_SK_LENGTH 0
#define MAX_SK_LENGTH 0xFFFFFFFF	//2^32 - 1

//types of Argon2
#define ARGON2D 0
#define ARGON2I 1
#define ARGON2ID 2

//Structure for the (1KB) 1024-bytes memory block implemented as 128 64-bit words
typedef struct { 
	uint64_t content[WORDS_IN_BLOCK]; 
} block;

//all the parameters are stored inside this struct
typedef struct{	
	//primary inputs
	uint8_t* psw;				//password
	uint8_t* salt;				//salt
	
	//secondary input
	uint32_t p;					//degree of parallelism i.e. number of lanes
	uint32_t T;					//tag length 
	uint32_t m;					//memory size
	uint32_t t;					//number of iterations
	uint32_t v;					//version number
	uint8_t* K;					//secret key (not necessary)
	uint8_t* X;					//associated data	
	uint32_t y;					//argon2 type (0=argon2d, 1 = argon2i, 2=argon2id)
	
	//ausiliary inputs (lengths)
	uint32_t length_psw;		//length of psw
	uint32_t length_salt;       //length of salt
	uint32_t length_K;          //length of secret key K
	uint32_t length_X;          //length of associated data X
	
	//other useful variables
	uint8_t* H_0;				//prehashing digest
	uint32_t m_prime;			//m_prime = 4 * p * ((uint32_t)floor(m / (4 * p))); 	
	uint32_t segment_length;	//segment_length = (uint32_t) ctx.q/4;
	uint32_t q;					//number of columns i.e. lane length

	//memory blocks
	block** B;          		//Memory pointer
	uint64_t** J;				//slice of J_1||J_2 values. Useful only in Argon2i - Argon2id
	
} argon2_ctx;


#endif