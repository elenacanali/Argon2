# Argon2
Password hashing scheme: Argon2 implementation

Argon2 is the winner of the Password Hashing Competition started in 2013. The implementation support three version of Argon2: Argon2d is faster and uses data depending memory access (suitable for cryptocurrencies and applications threatened by side-
channel attacks); Argon2i uses data independing memory access (to be preferred for password based key derivation and password hash-
ing); Argon2id is a hybrid between Argon2d and Argon2i.

Windows cmd compliler: gcc -fopenmp -o argon2 main.c common.h argon2_core.c argon2_core.h blake2blib.c blake2blib.h

Two option to run the program:
Cmd-> argon2 -P password -S somesalt (plus optional parameters)
File-> argon2 -IF
