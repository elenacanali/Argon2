#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<omp.h>

#include "blake2blib.h"
#include "common.h"


//creates a block with content equal to array
block bytes2block(uint8_t* array) {
	
	//init block
	block res;
	
	//copy 1024 bytes
	memcpy(res.content, array, 1024);

	return res;

}

//variable length hash function H' 
block H_prime(uint8_t* H_0, uint32_t n, uint32_t i, uint32_t tag_length){
		
	//allocate memory for the input of blake2b, we need a message_buffer of 76 bytes
	uint8_t* message_buffer = malloc(sizeof(uint8_t)*76);
	if(message_buffer == NULL) {
		printf("error in allocation memory for message_buffer\n");
		exit(1);
	}
		
	//put in the the first 4 bytes the value of tag length tag_length
	message_buffer[0] = (tag_length >> 0 ) & 0xFF;
	message_buffer[1] = (tag_length >> 8 ) & 0xFF;
	message_buffer[2] = (tag_length >> 16) & 0xFF;
	message_buffer[3] = (tag_length >> 24) & 0xFF;
	
	//then put H_0 as it is
	for(int j=0; j<64; j++) {
		message_buffer[j+4] = H_0[j];
	}
	
	//then put in the following 4 bytes the value of n
	message_buffer[68] = (n >> 0 ) & 0xFF;
	message_buffer[69] = (n >> 8 ) & 0xFF;
	message_buffer[70] = (n >> 16) & 0xFF;
	message_buffer[71] = (n >> 24) & 0xFF;
	
	//then put in the following bytes the value of i 
	message_buffer[72] = (i >> 0 ) & 0xFF;
	message_buffer[73] = (i >> 8 ) & 0xFF;
	message_buffer[74] = (i >> 16) & 0xFF;
	message_buffer[75] = (i >> 24) & 0xFF;
	
	if(tag_length <= 64) {
	
		//just hash the input with blake2b
		return bytes2block(getDigest_blake2b(message_buffer, 76, tag_length));
	} else {
	
		//find r
		int r;
		if(tag_length % 32 == 0) {
			r = ceil(tag_length/32) - 2;
		} else {
			r = ceil(tag_length/32) - 1;
		}
		
		//compute V_1 as the 64-byte digest of blake2b with message_buffer as input
		uint8_t* V = getDigest_blake2b(message_buffer, 76, 64);
				
		//allocate memory for the final_result we will return
		uint8_t* final_result = malloc(sizeof(uint8_t)*(32*r + (tag_length-32*r)));
		if(final_result == NULL) {
			printf("error in allocation memory for final_result\n");
			exit(1);
		}
		
		//copy the first 32 bytes of V_1 in final_result
		for(int j=0; j<32; j++) {
			final_result[j] = V[j];
		}
		
		//iteratively, compute V_2,..V_r and copy their first 32 bytes in final_result
		for(int k=1; k<r; k++){
			//compute V_1,...,V_r
			V = getDigest_blake2b(V, 64, 64);
			
			//append to final_result the first 32 bytes of every V_i for i=2,..r
			for(int j=0; j<32; j++) {
				final_result[j+32*k] = V[j];
			}
		}
		
		//lastly, compute V_{r+1} as the (tag_length-32*r)-bytes blake2b digest
		V = getDigest_blake2b(V, 64, (tag_length-32*r));
		
		//append V_{r+1} in final_result
		for(int j=0; j<(tag_length-32*r); j++) {
			final_result[j+32*r] = V[j];
		}
		
		//free memory
		free(V); free(message_buffer);
		
		return bytes2block(final_result);
	}
	
}

//allocate memory B, computes H_0 and fill first two columns of B
int init_argon2(argon2_ctx *ctx){

	//1. allocate memory
	(ctx->B) = malloc(ctx->p * sizeof(block *));
	if(ctx->B == NULL) {
		printf("errore nell'allocazione di B\n");
		return -1;
	}
	
	for(int i=0; i < ctx->p; i++) {
		ctx->B[i] = malloc(ctx->q * sizeof(block));
		if(ctx->B[i] == NULL) {
			printf("errore nell'allocazione di B[%d]\n",i);
			return -1;
		}
	}
	
	//2. compute H_0
	uint8_t* message_buffer = malloc(sizeof(uint8_t) * (40 + ctx->length_psw + ctx->length_salt + ctx->length_K + ctx->length_X));
	if(message_buffer == NULL) {
		printf("error in allocation memory for message_buffer\n");
		exit(1);
	}
		
	//initializing message_buffer
	//message_buffer[0..3] = p in bytes (little endian)
	message_buffer[0] = (ctx->p >> 0 ) & 0xFF;
	message_buffer[1] = (ctx->p >> 8 ) & 0xFF;
	message_buffer[2] = (ctx->p >> 16) & 0xFF;
	message_buffer[3] = (ctx->p >> 24) & 0xFF;
	
	//message_buffer[4..7] = T in bytes (little endian)
	message_buffer[4] = (ctx->T >> 0 ) & 0xFF;
	message_buffer[5] = (ctx->T >> 8 ) & 0xFF;
	message_buffer[6] = (ctx->T >> 16)& 0xFF;
	message_buffer[7] = (ctx->T >> 24)& 0xFF;
	
	//message_buffer[8..11] = m in bytes (little endian)
	message_buffer[8] =  (ctx->m >>  0 ) & 0xFF;
	message_buffer[9] =  (ctx->m >>  8 ) & 0xFF;
	message_buffer[10] = (ctx->m >> 16) & 0xFF;
	message_buffer[11] = (ctx->m >> 24) & 0xFF;
	
	//message_buffer[12..15] = t in bytes (little endian)
	message_buffer[12] = (ctx->t >> 0 ) & 0xFF;
	message_buffer[13] = (ctx->t >> 8 ) & 0xFF;
	message_buffer[14] = (ctx->t >> 16)& 0xFF;
	message_buffer[15] = (ctx->t >> 24)& 0xFF;
	
	//message_buffer[16..19] = v in bytes (little endian)
	message_buffer[16] = (ctx->v >> 0 ) & 0xFF;
	message_buffer[17] = (ctx->v >> 8 ) & 0xFF;
	message_buffer[18] = (ctx->v >> 16)& 0xFF;
	message_buffer[19] = (ctx->v >> 24)& 0xFF;
	
	//message_buffer[20..23] = y in bytes (little endian)
	message_buffer[20] = (ctx->y >> 0 ) & 0xFF;
	message_buffer[21] = (ctx->y >> 8 ) & 0xFF;
	message_buffer[22] = (ctx->y >> 16)& 0xFF;
	message_buffer[23] = (ctx->y >> 24)& 0xFF;
	
	//message_buffer[24..27] = ctx.length_psw in bytes (little endian)
	message_buffer[24] = (ctx->length_psw >> 0 ) & 0xFF;
	message_buffer[25] = (ctx->length_psw >> 8 ) & 0xFF;
	message_buffer[26] = (ctx->length_psw >> 16)& 0xFF;
	message_buffer[27] = (ctx->length_psw >> 24)& 0xFF;
	
	//message_buffer[28..28+ctx.length_psw-1] = psw in bytes as it is
	for(int i=0; i<ctx->length_psw; i++) {
		message_buffer[28+i] = ctx->psw[i];
	}
		
	//message_buffer[28+ctx.length_psw..31+ctx.length_psw] = ctx.length_salt in bytes (little endian)
	message_buffer[28 + ctx->length_psw] = (ctx->length_salt >> 0 ) & 0xFF;
	message_buffer[29 + ctx->length_psw] = (ctx->length_salt >> 8 ) & 0xFF;
	message_buffer[30 + ctx->length_psw] = (ctx->length_salt >> 16)& 0xFF;
	message_buffer[31 + ctx->length_psw] = (ctx->length_salt >> 24)& 0xFF;
	
	//message_buffer[32+ctx.length_psw..32+ctx.length_psw+ctx.length_salt-1] = salt in bytes as it is
	for(int i=0; i<ctx->length_salt; i++) {
		message_buffer[32+ctx->length_psw+i] = ctx->salt[i];
	}
	
	//message_buffer[32+ctx.length_psw+ctx.length_salt..35+ctx.length_psw] = ctx.length_K in bytes (little endian)
	message_buffer[32 + ctx->length_psw + ctx->length_salt] = (ctx->length_K >> 0 ) & 0xFF;
	message_buffer[33 + ctx->length_psw + ctx->length_salt] = (ctx->length_K >> 8 ) & 0xFF;
	message_buffer[34 + ctx->length_psw + ctx->length_salt] = (ctx->length_K >> 16)& 0xFF;
	message_buffer[35 + ctx->length_psw + ctx->length_salt] = (ctx->length_K >> 24)& 0xFF;
	
	//message_buffer[36+ctx.length_psw+ctx.length_salt..36+ctx.length_psw+ctx.length_salt+ctx.length_K-1] = K in bytes as it is
	for(int i=0; i<ctx->length_K; i++) {
		message_buffer[36+ctx->length_psw+ctx->length_salt+i] = ctx->K[i];
	}
	
	//message_buffer[36+ctx.length_psw+ctx.length_salt+ctx.length_K..39+ctx.length_psw+ctx.length_salt+ctx.length_K] = ctx.length_X in bytes (little endian)
	message_buffer[36 + ctx->length_psw + ctx->length_salt + ctx->length_K] = (ctx->length_X >> 0 ) & 0xFF;
	message_buffer[37 + ctx->length_psw + ctx->length_salt + ctx->length_K] = (ctx->length_X >> 8 ) & 0xFF;
	message_buffer[38 + ctx->length_psw + ctx->length_salt + ctx->length_K] = (ctx->length_X >> 16) & 0xFF;
	message_buffer[39 + ctx->length_psw + ctx->length_salt + ctx->length_K] = (ctx->length_X >> 24) & 0xFF;
	
	//message_buffer[32+ctx.length_psw..32+ctx.length_psw+ctx.length_salt] = X in bytes as it is
	for(int i=0; i<ctx->length_X; i++) {
		message_buffer[40+ctx->length_psw+ctx->length_salt+ctx->length_K+i] = ctx->X[i];
	}
	
	//find pre-hashing digest H_0
	ctx->H_0 = getDigest_blake2b(message_buffer, 40 + ctx->length_psw + ctx->length_salt + ctx->length_K + ctx->length_X, 64);
		
	//free message_buffer
	free(message_buffer);
	
	//3. compute first blocks
	for (int i = 0; i < ctx->p; i++) {
		ctx->B[i][0] = H_prime(ctx->H_0, 0, i, 1024);
		ctx->B[i][1] = H_prime(ctx->H_0, 1, i, 1024);
    }
		
	return 0;
}

//return the value of the first 32 bits of an uint64_t integer
uint64_t truncate(uint64_t a) {
	return a & 0xFFFFFFFF;
}

//mixing function very similar to the one in blake2b, but with multiplication. 
void Argon2_G(uint64_t* v, int a, int b, int c, int d) {
	
	//n.b. the 'mod 64' operation is done automatically since we are working with uint64_t
	v[a] = (v[a] + v[b] + 2 * truncate(v[a]) * truncate(v[b]));
	v[d] = rotational_shift_right((v[d] ^ v[a]), 32);
	v[c] = (v[c] + v[d] + 2 * truncate(v[c]) * truncate(v[d]));
	v[b] = rotational_shift_right((v[b] ^ v[c]), 24);
	
	v[a] = (v[a] + v[b] + 2 * truncate(v[a]) * truncate(v[b]));
	v[d] = rotational_shift_right((v[d] ^ v[a]), 16);
	v[c] = (v[c] + v[d] + 2 * truncate(v[c]) * truncate(v[d]));
	v[b] = rotational_shift_right((v[b] ^ v[c]), 63);
}

//permutation P
uint64_t* permutation_P(uint64_t* in){

	//we must find (uint64_t) v[0],..,v[15] from inputs
	uint64_t* v = malloc(sizeof(uint64_t)*16);
	if(v == NULL) {
		printf("error in allocation memory for v in permutation_P\n");
		exit(1);
	}
	
	//Inizializzo i v[i] a partire da block = S0||...||S7, dove Si = (v[2i+1] || v[2i])
    for (int i=0; i<8; i++) {
        memcpy(&v[2*i]  ,&in[2*i]  ,8);
        memcpy(&v[2*i+1],&in[2*i+1],8);
    }
		
	//apply function G 8 times
	Argon2_G(v, 0, 4, 8 , 12);
	Argon2_G(v, 1, 5, 9 , 13);
	Argon2_G(v, 2, 6, 10, 14);
	Argon2_G(v, 3, 7, 11, 15);
	
	Argon2_G(v, 0, 5, 10, 15);
	Argon2_G(v, 1, 6, 11, 12);
	Argon2_G(v, 2, 7, 8 , 13);
	Argon2_G(v, 3, 4, 9 , 14);
	
	return v;
}

//compression function
block Argon2_compression_function(block first_block, block second_block){
	
	//1. allocation for R, a 128-words vector where we put the XOR of the two blocks
	uint64_t* R = malloc(128 * sizeof(uint64_t));
	if(R == NULL) {
		printf("error in allocation memory for R\n");
		exit(1);
	}
	
	//XOR
	for(int i=0; i<128; i++) {
		R[i] = first_block.content[i] ^ second_block.content[i];
	}
	
	
	//2. Apply permutation_P row-wise and put the results in Q
	uint64_t* Q[8];

    for (int i=0; i<8; i++) {
        Q[i] = permutation_P(R + 16*i);
	}
	
	//3. we take the columns of Q and put them in column0,...,column7
    uint64_t * column0 = (uint64_t *)malloc(16 * sizeof(uint64_t));
    uint64_t * column1 = (uint64_t *)malloc(16 * sizeof(uint64_t));
    uint64_t * column2 = (uint64_t *)malloc(16 * sizeof(uint64_t));
    uint64_t * column3 = (uint64_t *)malloc(16 * sizeof(uint64_t));
    uint64_t * column4 = (uint64_t *)malloc(16 * sizeof(uint64_t));
    uint64_t * column5 = (uint64_t *)malloc(16 * sizeof(uint64_t));
    uint64_t * column6 = (uint64_t *)malloc(16 * sizeof(uint64_t));
    uint64_t * column7 = (uint64_t *)malloc(16 * sizeof(uint64_t));

    for (int i=0; i<8; i++) {
        memcpy(column0+2*i, Q[i]+2*0,16);
        memcpy(column1+2*i, Q[i]+2*1,16);
        memcpy(column2+2*i, Q[i]+2*2,16);
        memcpy(column3+2*i, Q[i]+2*3,16);
        memcpy(column4+2*i, Q[i]+2*4,16);
        memcpy(column5+2*i, Q[i]+2*5,16);
        memcpy(column6+2*i, Q[i]+2*6,16);
        memcpy(column7+2*i, Q[i]+2*7,16);
    }
	
	//free Q
	for(int i=0; i<8; i++) {
		free(Q[i]);
	}
	
	//4. Z is an array of pointers to uint64_t*, we apply permutation_P
	uint64_t* Z[8];
	
    Z[0] = permutation_P(column0); 
	Z[1] = permutation_P(column1); 
	Z[2] = permutation_P(column2); 
	Z[3] = permutation_P(column3); 
	Z[4] = permutation_P(column4); 
	Z[5] = permutation_P(column5); 
	Z[6] = permutation_P(column6); 
	Z[7] = permutation_P(column7);
	
	//we take the columns of Z and we put them in column0,...,column7
    for (int i=0; i<8; i++) {
        memcpy(column0+2*i, Z[i]+2*0,16);
        memcpy(column1+2*i, Z[i]+2*1,16);
        memcpy(column2+2*i, Z[i]+2*2,16);
        memcpy(column3+2*i, Z[i]+2*3,16);
        memcpy(column4+2*i, Z[i]+2*4,16);
        memcpy(column5+2*i, Z[i]+2*5,16);
        memcpy(column6+2*i, Z[i]+2*6,16);
        memcpy(column7+2*i, Z[i]+2*7,16);
    }
	
	//free Z
	for(int i=0; i<8; i++) {
		free(Z[i]);
	}
	
	//5. Allocation for result
	uint64_t* result = malloc(128 * sizeof(uint64_t));
	if(result == NULL) {
		printf("error in allocation memory for result in Argon2_compression_function\n");
		exit(1);
	}
	
	//6. Put in result the XOR Z ^ R
    for (int i=0;i<16;i++) {
        result[16*0 + i] = R[16*0 + i] ^ column0[i];
        result[16*1 + i] = R[16*1 + i] ^ column1[i];
        result[16*2 + i] = R[16*2 + i] ^ column2[i];
        result[16*3 + i] = R[16*3 + i] ^ column3[i];
        result[16*4 + i] = R[16*4 + i] ^ column4[i];
        result[16*5 + i] = R[16*5 + i] ^ column5[i];
        result[16*6 + i] = R[16*6 + i] ^ column6[i];
        result[16*7 + i] = R[16*7 + i] ^ column7[i];
    }
	
	//7. put the result in a block
	block res;
	memcpy(res.content, result, 1024);
	
	//8. free memory
	free(R); free(result);
	
    free(column0); 
	free(column1); 
	free(column2);
	free(column3); 
	free(column4);
	free(column5);
	free(column6); 
	free(column7);
	
	return res;
}

//XOR two block bytes
block XOR_blocks(block first_block, block second_block) {
	
	//initialize res
	block res;
	
	//xor
	for(int i=0; i<128; i++) {
		res.content[i] = first_block.content[i] ^ second_block.content[i];
	}
	
	return res;
}

//indexing function
block indexing_block(argon2_ctx *ctx, uint32_t passo, uint32_t slice, uint32_t i, uint32_t j){

	//1. Find J_1 and J_2, according to type of argon2
	uint32_t j_abs = j + slice*ctx->segment_length;
	uint64_t J_1 = 0;
	uint64_t J_2 = 0;
	uint8_t *pair = calloc(8,sizeof(uint8_t));
		
	//N.B: here j is the relative position (0...segment_length), j_abs instead is the absolute one (0..q-1)
	switch(ctx->y) {
		case ARGON2D :
			//dependent indexing da B
			if(j_abs != 0) {
				memcpy(pair, &(ctx->B[i][j_abs-1]) 	, 8);		//copy the pair J1||J2 from the first 8 bytes of the previous block 
				memcpy(&J_1, pair					, 4);   	//initialize J_1
				memcpy(&J_2, pair + 4				, 4);   	//initialize J_2
			} else {         
				memcpy(pair, &(ctx->B[i][ctx->q - 1])   , 8);	//copy the pair J1||J2 from the first 8 bytes from block B[i][q - 1]
				memcpy(&J_1, pair						, 4);   //initialize J_1
				memcpy(&J_2, pair + 4					, 4);   //initialize J_2
			}
			break;
		case ARGON2I :
			memcpy(pair, &(ctx->J[i][j % 128])	, 8);			//copy the pair J1||J2 from the 8 bytes of J[i] which are in position j%128
			memcpy(&J_1, pair    				, 4);   		//initialize J_1
			memcpy(&J_2, pair + 4				, 4);   		//initialize J_2
			break;
		case ARGON2ID :
			if((passo == 0) && (slice == 0 || slice == 1)) {
				//Argon2i style
				memcpy(pair, &(ctx->J[i][j % 128])  , 8);
				memcpy(&J_1, pair    				, 4);
				memcpy(&J_2, pair + 4				, 4);
			} else {
				//Argon2d style
				if(j_abs != 0) {
					memcpy(pair, &(ctx->B[i][j_abs-1]) 	, 8);
					memcpy(&J_1, pair					, 4);
					memcpy(&J_2, pair + 4				, 4);
				} else {         
					memcpy(pair, &(ctx->B[i][ctx->q - 1])   , 8);
					memcpy(&J_1, pair						, 4);
					memcpy(&J_2, pair + 4					, 4);
				}
			}
			break;
	}

	//2. Find the lane number from which the block will be taken
    uint32_t lane;

    //If we work with the first slice and the first pass, l is set to the
    //current lane index, else l = J2 mod p
    if((passo == 0) && (slice == 0)) {
        lane = i;
    } else {
        lane = J_2 % ctx->p;
	}
	
	//3. Find where we have to start and stop the referencing
    uint32_t min_j, max_j;
	
    if(lane == i) {
        //in the "same lane" case
        if (passo == 0) {
			//if we are in first pass, take all the blocks until j_abs-2
            min_j = 0;
            max_j = j_abs-2; 
        } else {
			//otherwise, take all the blocks in the other 3 slices
			//and also all the blocks in this slice unti j_abs-2
            min_j = (slice+1) * ctx->segment_length; 
            max_j = ctx->q + j_abs-2;
        }
    }
    else {
        //different lane case
        if (passo == 0) {
			//if we are in first pass, take all the blocks of the already computed slices
            min_j = 0; 
            max_j = slice*ctx->segment_length - 1;
        } else {
			//otherwise, take all the blocks in the other 3 slices
            min_j = (slice+1)*ctx->segment_length;
            max_j = ctx->q + slice*ctx->segment_length - 1;       
        }
        // Only when different lanes : if the current block is at the beginning of a segment, 
        // B[i][j] is exluded
        if (j_abs % ctx->segment_length == 0) {
            max_j--;
		}
    } 
	
    //The size of R, the reference set
    uint64_t R_size = max_j - min_j + 1;

    //Computation of the block number
    uint64_t x = ((J_1)*(J_1)) >> 32;
    uint64_t z = R_size - 1 - ((R_size*x) >> 32);

	//free pointer
	free(pair);
	
    //Retrieving the pointer to the block 
    return ctx->B[lane][(min_j+z) % ctx->q];
}

//used in Argon2i and Argon2id
block CounterMode_compression(uint64_t* input) {

	//initialize block all 0 and block from input
	uint64_t * zero_block = (uint64_t *)calloc(128,sizeof(uint64_t));
    block zero;
	memcpy(zero.content, zero_block, 1024);
	
	block input_block;
	memcpy(input_block.content, input, 1024);
	
	//apply 2 time the compression functon with zero as first input each time
    block R1 = Argon2_compression_function(zero, input_block);
    block R2 = Argon2_compression_function(zero, R1);
	
	//free memory
	free(zero_block);

    return R2;

}

//write an 64-bit array of length 128 for the segment i
void computeJ(argon2_ctx *ctx,  uint32_t passo, uint32_t slice, uint32_t i, uint32_t j, uint32_t counter) {
	
	//allocate the input block
	uint64_t* input = calloc(128, sizeof(uint64_t));
	if(input == NULL) {
		printf("errore in allocazione input in indexing_block\n");
		exit(1);
	}        

	//initialize input
	memcpy(input 	, &passo		, 4);
	memcpy(input + 1, &i			, 4);
	memcpy(input + 2, &slice		, 4);
	memcpy(input + 3, &ctx->m_prime	, 4);
	memcpy(input + 4, &ctx->t		, 4);
	memcpy(input + 5, &ctx->y		, 4);
	memcpy(input + 6, &counter		, 4);

	//apply CounterMode_compression and put result in J[i]
	block Jsegment = CounterMode_compression(input);
	memcpy(ctx->J[i], Jsegment.content, 1024);
	
	//free memory	
	free(input);

	return;
}

//main function, it fills all the blocks in B
void fill_memory(argon2_ctx *ctx){
	
	//just for make the code shorter
	uint32_t sl = ctx->segment_length;
	uint32_t passo = 0;
	
	while(passo < ctx->t) {
		//while conta le iterazioni
		for(uint32_t slice=0; slice < 4; slice++) {
			//for che cambia slices
			#pragma omp parallel num_threads(ctx->p)
			//iniziamo la parallelizzazione ora con p threads
			{
				#pragma omp for
				//con questo comando l'esecuzione del for è distribuita nei p threads; ATTENZIONE è necessario compilare aggiungendo -fopenmp
					for(uint32_t i=0; i<ctx->p; i++) {
						//for che scorre le righe della slice in questione
						for(uint32_t j = (((passo == 0) && (slice == 0)) ? 2 : 0); j < sl; j++) {
							//for che scorre le colonne della slice che stiamo processando	
							//iniziamo da 2 se siamo al primo passo, prima slice
							//perchè in questo caso abbiamo già inizializzato le prime 2 colonne 
							
							if((ctx->y == ARGON2I) && ((j % 128 == 0) || (j == 2 && passo == 0 && slice == 0))) {
								//in Argon2i dobbiamo creare un nuovo blocco di J1||J2 
								//associato al segmento che stiamo inizializzando
								computeJ(ctx, passo, slice, i, j, j/128+1);
							}
							
							if((ctx->y == ARGON2ID) && (passo == 0) && (slice == 0 || slice == 1) && ((j % 128 == 0) || (j == 2 && slice == 0))) {
								//in Argon2id dobbiamo creare un nuovo blocco di J1||J2 
								//associato al segmento che stiamo inizializzando ma solo nel caso passo = 0 e slice = 0 o 1.
								computeJ(ctx, passo, slice, i, j, j/128+1);
							}
							
							if (passo == 0) {
								//al primo passo non abbiamo lo xor
								ctx->B[i][j + sl*slice] = Argon2_compression_function(ctx->B[i][j-1 + sl*slice], indexing_block(ctx, passo, slice, i, j));
							}
							else {
								//dal secondo passo in poi, abbiamo lo xor. Se stiamo in posizione [i][0]
								//(cioè slice è 0, j è 0) dobbiamo prendere il blocco [i][q-1]. 
								if((j == 0) && (slice == 0)) {
									ctx->B[i][j + sl*slice] = XOR_blocks(ctx->B[i][j + sl*slice], \
									Argon2_compression_function(ctx->B[i][ctx->q-1], indexing_block(ctx, passo, slice, i, j)));
								} else { 
									ctx->B[i][j + sl*slice] = XOR_blocks(ctx->B[i][j + sl*slice], \
									Argon2_compression_function(ctx->B[i][j-1 + sl*slice], indexing_block(ctx, passo, slice, i, j)));
								}
							}
						}
					}
			}
		}
		passo++;
	}
			
}

//Xor the last column in B, hash the result to obtain C and get the tag
uint8_t* finalize(argon2_ctx *ctx){
	
	//0. free J if we are using Argon2i or Argon2id
	if(ctx->y == ARGON2I || ctx->y == ARGON2ID) {
		for(uint32_t i=0; i<ctx->p; i++) {
			free(ctx->J[i]);
		}
		free(ctx->J);
	}

	//1. XOR all the blocks inside the last column
	block C = ctx->B[0][ctx->q-1];
	
	for(uint32_t i=1; i<ctx->p; i++) {
		C = XOR_blocks(ctx->B[i][ctx->q-1], C);
	}
	
	//2. Hash C in order to obtain the final TAG
	uint8_t *bytes_block = calloc(1024, sizeof(uint8_t));
	memcpy(bytes_block, C.content, 1024);
	
	//allocation for the input of blake2b
	uint8_t* message_buffer = malloc(sizeof(uint8_t)*1024+4);
	if(message_buffer == NULL) {
		printf("error in allocation memory for message_buffer\n");
		exit(1);
	}
		
	//put in the the first 4 bytes the value of tag length
	message_buffer[0] = (ctx->T >> 0 ) & 0xFF;
	message_buffer[1] = (ctx->T >> 8 ) & 0xFF;
	message_buffer[2] = (ctx->T >> 16) & 0xFF;
	message_buffer[3] = (ctx->T >> 24) & 0xFF;
	
	//then put C as it is
	for(int j=0; j<1024; j++) {
		message_buffer[j+4] = bytes_block[j];
	}
	
	//2.5. free memory B
	for(uint32_t i=0; i<ctx->p; i++) {
		free(ctx->B[i]);
	}
	free(ctx->B);

		
	//3. Apply sort of H_prime to get the tag
	if(ctx->T <= 64) {
		return getDigest_blake2b(message_buffer, 1028, ctx->T);
	} else {
		//find r
		int r;
		if(ctx->T % 32 == 0) {
			r = ceil(ctx->T/32) - 2;
		} else {
			r = ceil(ctx->T/32) - 1;
		}
		
		//allocate memory for the final_result we will return
		uint8_t* final_result = malloc(sizeof(uint8_t)*ctx->T);
		if(final_result == NULL) {
			printf("error in allocation memory for final_result\n");
			exit(1);
		}
		
		//compute V_1 as the 64-byte digest of blake2b with message_buffer as input
		uint8_t* V = getDigest_blake2b(message_buffer, 1028, 64);
		
		//copy the first 32 bytes of V_1 in final_result
		for(int j=0; j<32; j++) {
			final_result[j] = V[j];
		}
		
		//iteratively, compute V_2,..V_r and copy their first 32 bytes in final_result
		for(int k=1; k<r; k++){
			//compute V_1,...,V_r
			V = getDigest_blake2b(V, 64, 64);
			
			//append to final_result the first 32 bytes of every V_i for i=2,..r
			for(int j=0; j<32; j++) {
				final_result[j+32*k] = V[j];
			}
		}
		
		//lastly, compute V_{r+1} as the (tag_length-32*r)-bytes blake2b digest
		V = getDigest_blake2b(V, 64, (ctx->T-32*r));
		
		//append V_{r+1} in final_result
		for(int j=0; j<(ctx->T-32*r); j++) {
			final_result[j+32*r] = V[j];
		}
		
		//free memory
		free(V); free(bytes_block);
		
		return final_result;
	}

}

//apply init_argon2, fill_memory and finalize 
uint8_t* getTag_argon2(argon2_ctx *ctx) {
	
	//1. Initialization: Hashing inputs, allocating memory, filling first blocks
    init_argon2(ctx);
	
	//Init J if we need it (Argon2i or Argon2id)
	if(ctx->y == ARGON2I || ctx->y == ARGON2ID) {
		ctx->J = malloc(ctx->p * sizeof(uint64_t*));
		for(int i=0; i<ctx->p; i++) {
			ctx->J[i] = calloc(128, sizeof(uint64_t));
		}
	}
	
	//2. Filling memory
    fill_memory(ctx);
	
	
	//3. Finalization
	return finalize(ctx);

}