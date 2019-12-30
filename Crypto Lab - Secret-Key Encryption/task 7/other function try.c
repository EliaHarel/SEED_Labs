
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define CLOSE_FILES fclose(plain);fclose(words);fclose(out);

void strcpy2(unsigned char dest[], char* src){
    while(*dest++ = *src++);
}

int do_crypt(char* outfile, unsigned char key[]);


void get_new_key(FILE* words, unsigned char key[17]){
    for(int j = 0; j < 17; j++) key[j] = '\0';
    size_t len = 0;
    char* line = 0;
    getline(&line, &len, words);
    strcpy2(key, line);
    if(strlen(key) < 17){
        int i = strlen(key);
        i--;
        while(i < 16) key[i++] = '#';
        key[16] = '\0';
    }
}

//key - 
//10th############
//cipher text is: 
//0c1a6d1f180a3173244ef96a08684e7912832c8e56ca214f1fdf6e3c192af75d
int main(){
    unsigned char iv_aux[] = "aabbccddeeff00998877665544332211";
    unsigned char* iv = iv_aux;
    //dont with IV
    //unsigned char ciphertext[] = "062ff0112cb32d04d0adcfa02d215abd40a5f932da1ebbd3744de5d16be5a4d7";
//the example one
    unsigned char ciphertext[] = "0c1a6d1f180a3173244ef96a08684e7912832c8e56ca214f1fdf6e3c192af75d";
    unsigned char key[17];
    unsigned char cipher_for_check[65];
    //opening files
    FILE* plain = fopen("./file", "r");
    if(plain == NULL) return -1;
    FILE* words = fopen("./words.txt", "r");
    if(words == NULL){
        fclose(plain);
        return -1;
    }
    FILE* out = fopen("./out.txt", "rw");
    if(out == NULL){
        fclose(plain);
        fclose(words);
        return -1;
    }
    bool not_found = true;
    while(not_found){
        get_new_key(words, key);
        if( do_crypt("./out.txt",key) == 2) not_found=false;
    }
    CLOSE_FILES
    return 0;
}


int do_crypt(char* outfile, unsigned char key[]){
    unsigned char outbuf[1024];
    int outlen, tmplen;
    unsigned char iv[] = {a, a, b, b, c, c, d, d, e, e, f, f, 0, 0, 9, 9, 8, 8, 7, 7, 6, 6, 5, 5, 4, 4, 3, 3, 2, 2, 1, 1};
    char intext[] = "This is a top secret.";
    EVP_CIPHER_CTX* ctx;
    FILE* out;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_idea_cbc(), NULL, key, iv);
    if(!EVP_EncryptUpdate(ctx, outbuf, &outlen, intext, strlen(intext))){
        /* Error */
        return 0;
    }
    /* Buffer passed to EVP_EncryptFinal() must be after data just
     * encrypted to avoid overwriting it.
     */
    if(!EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen)){
        /* Error */
        return 0;
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    /* Need binary mode for fopen because encrypted data is
     * binary data. Also cannot use strlen() on it because
     * it won't be null terminated and may contain embedded
     * nulls.
     */

for(int ij=0; ij<outlen;ij++){
  if(outbuf[ij]!=ciphertext[ij]) break;
  if(ij==outlen-1) printf("%s\n", key);
  return 2;
}
    out = fopen(outfile, "wb");
    fwrite(outbuf, 1, outlen, out);
    fclose(out);
    return 1;
}
