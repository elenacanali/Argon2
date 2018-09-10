#include<stdio.h>
#include<stdlib.h>
#include<stdbool.h>
#include<stdint.h>
#include<math.h>
#include<stddef.h>
#include<string.h>
#include<ctype.h>

#define NUMBER_OF_ROUNDS 12
#define NUMBER_OF_BYTES_IN_BLOCK 128
#define NUMBER_OF_WORDS_IN_BLOCK 16

#define NELEMS(x) (sizeof(x) / sizeof((x)[0]))

#ifndef BLAKE2B_HLIB
#define BLAKE2B_HLIB

//blake2b initial vectors
static const uint64_t initial_vectors[8] = {
	0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
	0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
	0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
	0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

//blake2b permutations, used in compression function F
//row i is equal to sigma_i, with i=0,...,11 because we have 12 rounds
//sigma_i(j) is equal to the element sigma[i][j], with j=0...15
static const uint8_t sigma[12][16] = {
	{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
	{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
	{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
	{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
	{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
	{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
	{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
	{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
	{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
	{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
};

//struct data_block, where we put the necessary information about m^i, the i-th block
typedef struct {	
	uint64_t m[NUMBER_OF_WORDS_IN_BLOCK];		//words in a block (16 uint64_t words == 128 byte)
	uint64_t t[2];								//total number of bytes in the message input (until and including this block)
	bool f_0;									//finalization flag
} data_block;


//rotational shift of a 64-bit word to the right
uint64_t rotational_shift_right(uint64_t v, int value);

//initialize a data block with default values
void init_block(data_block *block);

//initialize field m of a block 
void initialize_field_m(uint64_t* word_to_initialize, uint8_t* word_address_from_buffer);

//mixing function G
void mixing_function_G(uint64_t *v, uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint64_t x, uint64_t y);

//compression function F
void compression_function_F(uint64_t* h, data_block block);

//main function, output the blake2b digest 
uint8_t* getDigest_blake2b(uint8_t* message_buffer, int n, size_t digest_length);

#endif