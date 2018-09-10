#ifndef ARGON2_CORE_H
#define ARGON2_CORE_H

#include "blake2blib.h"
#include "common.h"

//creates a block with content equal to array
block bytes2block(uint8_t* array);

//variable length hash function H' 
block H_prime(uint8_t* H_0, uint32_t n, uint32_t i, uint32_t tag_length);

//allocate memory B, computes H_0 and fill first two columns of B
int init_argon2(argon2_ctx *ctx);

//return the value of the first 32 bits of an uint64_t integer
uint64_t truncate(uint64_t a);

//mixing function very similar to the one in blake2b, but with multiplication. 
void Argon2_G(uint64_t* v, int a, int b, int c, int d);

//permutation P
uint64_t* permutation_P(uint64_t* in);

//compression function
block Argon2_compression_function(block first_block, block second_block);

//XOR two block bytes
block XOR_blocks(block first_block, block second_block);

//indexing function
block indexing_block(argon2_ctx *ctx, uint32_t passo, uint32_t slice, uint32_t i, uint32_t j);

//used in Argon2i and Argon2id
block CounterMode_compression(uint64_t* input);

//write J[i], an 64-bit array of length 128 for the segment i
void computeJ(argon2_ctx *ctx,  uint32_t passo, uint32_t slice, uint32_t i, uint32_t j, uint32_t counter);

//main function, it fills all the blocks in B
void fill_memory(argon2_ctx *ctx);

//Xor the last column in B, hash the result to obtain C and get the tag
uint8_t* finalize(argon2_ctx *ctx);

//apply init_argon2, fill_memory and finalize 
uint8_t* getTag_argon2(argon2_ctx *ctx);

#endif