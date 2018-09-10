#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<math.h>
#include<stdbool.h>
#include<stddef.h>
#include<string.h>
#include<ctype.h>

#include "blake2blib.h"

//rotate a 64 bit word to the right by value
uint64_t rotational_shift_right(uint64_t v, int value){
	
	return ((v) >> (value)) ^ ((v) << (64-value));
}

//initialize field m of a data_block 
void initialize_field_m(uint64_t* word_to_initialize, uint8_t* word_address_from_buffer){

	*word_to_initialize = ((uint64_t) word_address_from_buffer[0]) ^ \
	(((uint64_t) word_address_from_buffer[1]) << 8) ^ \
	(((uint64_t) word_address_from_buffer[2]) << 16) ^ \
	(((uint64_t) word_address_from_buffer[3]) << 24) ^ \
	(((uint64_t) word_address_from_buffer[4]) << 32) ^ \
	(((uint64_t) word_address_from_buffer[5]) << 40) ^ \
	(((uint64_t) word_address_from_buffer[6]) << 48) ^ \
	(((uint64_t) word_address_from_buffer[7]) << 56);
	
}

//initialize a data block with default values
void init_block(data_block *block) {
	
	for(int j=0; j<NUMBER_OF_WORDS_IN_BLOCK; j++) {
		block->m[j] = 0x0;
	}
	block->t[0] = 0x0;
	block->t[1] = 0x0;
	block->f_0 = false;
	
} 

//mixing function G
void mixing_function_G(uint64_t *v, uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint64_t x, uint64_t y ){
	
	//n.b. the 'mod 64' operation is done automatically since we are working with uint64_t
	v[a] = (v[a] + v[b] + x);
	v[d] = rotational_shift_right((v[d] ^ v[a]), 32);
	v[c] = (v[c] + v[d]);
	v[b] = rotational_shift_right((v[b] ^ v[c]), 24);
	v[a] = (v[a] + v[b] + y);
	v[d] = rotational_shift_right((v[d] ^ v[a]), 16);
	v[c] = (v[c] + v[d]);
	v[b] = rotational_shift_right((v[b] ^ v[c]), 63);
}

//compression function F 
void compression_function_F(uint64_t* h, data_block block){
	
	//allocate memory for array v
	uint64_t *v = malloc(sizeof(uint64_t)*16);
	if(v == NULL) {
		printf("error in allocation memory for v in compression_function_F\n");
		exit(1);
	}
	
	//initialize v[0..15]
	for(int i=0; i<8; i++) {
		v[i] = h[i];
		v[i+8] = initial_vectors[i];
	}

	v[12] = v[12] ^ (block.t[0]);	//low word xor
	v[13] = v[13] ^ (block.t[1]);	//high word xor
	
	
	//if last block is processed v[14] is modified (xored with 11...11)
	if(block.f_0 == true) {
		v[14] = v[14] ^ 0xffffffffffffffff;
	}
		
	//doing the rounds
	for(int i=0; i < NUMBER_OF_ROUNDS; i++) {
		
		mixing_function_G(v,0,	4,	8,	12, block.m[sigma[i][0]], 	block.m[sigma[i][1]]);
		mixing_function_G(v,1,	5,	9,	13, block.m[sigma[i][2]], 	block.m[sigma[i][3]]);
		mixing_function_G(v,2,	6,	10,	14,	block.m[sigma[i][4]], 	block.m[sigma[i][5]]);
		mixing_function_G(v,3,	7,	11,	15,	block.m[sigma[i][6]], 	block.m[sigma[i][7]]);
				
		mixing_function_G(v,0,	5,	10,	15,	block.m[sigma[i][8]], 	block.m[sigma[i][9]]);
		mixing_function_G(v,1,	6,	11,	12,	block.m[sigma[i][10]],	block.m[sigma[i][11]]);
		mixing_function_G(v,2,	7,	8,	13,	block.m[sigma[i][12]],	block.m[sigma[i][13]]);
		mixing_function_G(v,3,	4,	9,	14,	block.m[sigma[i][14]],	block.m[sigma[i][15]]);
	}			
	
	//update the "state" h
	for(int i=0; i<8; i++) {
		h[i] = h[i] ^ v[i] ^ v[i+8];
	}
	
	//free memory after allocation
	free(v);
}

//executing blake2b
uint8_t* getDigest_blake2b(uint8_t* message_buffer, int n, size_t digest_length) {

	//check if digest_length is in 1..64
	if (digest_length == 0 || digest_length > 64){
		printf("digest length not valid!\n");
		return NULL; // illegal parameter
	}
	
	//compute number of blocks and total number of bytes needed
	int total_number_of_bytes;
	if(n % 128 == 0) {
		total_number_of_bytes = n;
	} else {
		total_number_of_bytes = n + (NUMBER_OF_BYTES_IN_BLOCK - (n % 128));
	}
	int number_of_blocks = total_number_of_bytes/NUMBER_OF_BYTES_IN_BLOCK;
	
	//allocate a data_block vector with size equal to number_of_blocks
	data_block* blocks = malloc(sizeof(data_block)*number_of_blocks);
	if(blocks==NULL){
		printf("error in allocation memory for blocks in getDigest_blake2b\n");
		exit(1);
	}
	
	//padding message_buffer
	uint8_t padded_message[total_number_of_bytes];
	for(int i=0; i<n; i++) {
		padded_message[i] = message_buffer[i];
	}
	for(int i=n; i<total_number_of_bytes; i++) {
		padded_message[i] = 0x0;
	}

	//initialize all the blocks with adeguate values
	for(int i=0; i<number_of_blocks; i++){
		
		//initialize first all the blocks with default values
		init_block(&blocks[i]);	
		
		//initialize field m for all the blocks
		for(int j=0; j<NUMBER_OF_WORDS_IN_BLOCK; j++) {
			initialize_field_m(&blocks[i].m[j], (padded_message +(128 * i + 8 * j)));
		}
		//set field's counter t[0], t[1] and flag
		if(i == number_of_blocks-1) {
			//surely in this case t[1] does not increase
			blocks[i].f_0 = true;
			blocks[i].t[0] = n;
		} else { 
			//check first if we must increase t[1]
			if(NUMBER_OF_BYTES_IN_BLOCK*i + NUMBER_OF_BYTES_IN_BLOCK == 0) {
					blocks[i].t[1]++;
					printf("to be implemented\n"); exit(1);
				}
			blocks[i].t[0] = NUMBER_OF_BYTES_IN_BLOCK*(i+1);
		}
	}
	
	//initialize state vector h
	uint64_t h[8];
	for(int i = 0; i < 8; i++) {
		h[i] = initial_vectors[i];
	}
	
	//generate h^0 = h[0..7]. For doing this we must only change h[0] as follows
	h[0] ^= 0x01010000 ^ digest_length;
	

	//apply compression function number_of_blocks times
	for(int i=0; i<number_of_blocks; i++) {
		compression_function_F(h, blocks[i]);	
	}
	
	//allocation of memory for digest 
	uint8_t* digest = malloc(sizeof(uint8_t)*digest_length);
	if(digest==NULL){
		printf("error in allocation memory for digest in getDigest_blake2b\n");
		exit(1);
	}
	
	//little endian all the words in h, h[0]..h[7] and put them in digest
	for(int i=0; i<digest_length; i++) {
		digest[i] = (uint8_t) (h[i>>3] >> (8 * (i & 7)));
	}
	
	//free memory
	free(blocks);
	
	return digest;

}



