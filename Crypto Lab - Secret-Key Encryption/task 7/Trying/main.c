#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define CLOSE_FILES fclose(plain);fclose(words);fclose(out);

void strcpy2(unsigned char dest[], char* src){
    int i = 0;
    while(src[i] != '\0' && src[i] != '\n'){
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

int do_crypt(FILE* in, FILE* out, int do_encrypt, unsigned char iv[], unsigned char key[]);

void get_new_key(FILE* words, unsigned char key[17]){
    size_t len = 0;
    char* line = 0;
    getline(&line, &len, words);
    strcpy2(key, line);
    if (strlen(key)<17){
        int i = strlen(key);
        while(i<16) key[i++] = '#';
        key[16]='\0';

    }
}

int main(){
    unsigned char iv_aux[] = "226943873990930483007034637375096693265";
    unsigned char* iv = iv_aux;
    //dont with IV

    unsigned char ciphertext[] = "062ff0112cb32d04d0adcfa02d215abd40a5f932da1ebbd3744de5d16be5a4d7";
    unsigned char key[17];
    unsigned char cipher_for_check[64];

    //opening files
    FILE* plain = fopen("../file", "r");
    if(plain == NULL) return -1;
    FILE* words = fopen("../words.txt", "r");
    if(words == NULL){
        fclose(plain);
        return -1;
    }
    FILE* out = fopen("../out", "w");
    if(out == NULL){
        fclose(plain);
        fclose(words);
        return -1;
    }
    //done with files


    //try the keys
    bool not_found = true;
    while(not_found){

        get_new_key(words, key);
       do_crypt(plain, out, 1, iv, key);
        size_t len = 0;
        char* line = 0;
        getline(&line, &len, out);
        strcpy2(cipher_for_check, line);

        if(!(strcmp(cipher_for_check, ciphertext))){
            printf("key is: %s\n", key);
            not_found = false;
        }else{
            fclose(plain);
            plain = fopen("./file", "r");
        }
    }
    CLOSE_FILES

    return 0;
}


int do_crypt(FILE* in, FILE* out, int do_encrypt, unsigned char iv[], unsigned char key[]){
//     Allow enough space in output buffer for additional block
   unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
   int inlen, outlen;
   EVP_CIPHER_CTX* ctx_t = EVP_CIPHER_CTX_new();

   // Don't set key or IV right away; we want to check lengths
   EVP_CIPHER_CTX_init(ctx_t);
   EVP_CipherInit_ex(ctx_t, EVP_aes_128_cbc(), NULL, NULL, NULL,
                     do_encrypt);
   OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx_t) == 16);
   OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx_t) == 16);
   // Now we can set key and IV
   EVP_CipherInit_ex(ctx_t, NULL, NULL, key, iv, do_encrypt);
   for(;;){
       inlen = fread(inbuf, 1, 1024, in);
       if(inlen <= 0) break;
       if(!EVP_CipherUpdate(ctx_t, outbuf, &outlen, inbuf, inlen)){
           // Error
           EVP_CIPHER_CTX_cleanup(ctx_t);
           return 0;
       }
       fwrite(outbuf, 1, outlen, out);
   }
   if(!EVP_CipherFinal_ex(ctx_t, outbuf, &outlen)){
       // Error
       EVP_CIPHER_CTX_cleanup(ctx_t);
       return 0;
   }
   fwrite(outbuf, 1, outlen, out);
   EVP_CIPHER_CTX_cleanup(ctx_t);
   return 1;
}

