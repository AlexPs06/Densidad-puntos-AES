#include <wmmintrin.h>
#include <immintrin.h>
#include <emmintrin.h>
#include <pmmintrin.h>
#include <stdio.h>
#include <stdbool.h>

void print_hex_string(unsigned char* buf, int len);
void counter_mode(unsigned char plaintext[],unsigned char N[],unsigned char key[],int size, unsigned char ciphertext[] );
void chaining_block_cipher_MAC(unsigned char plaintext[],unsigned char N[],unsigned char key[],unsigned char T[],int size );
int serach_period_point(__m128i pt,__m128i ct, __m128i key );

#define MESSAGE_LENGHT 16
#define ALIGN(n) __attribute__ ((aligned(n)))
#define EXPAND_ASSIST(v1,v2,v3,v4,shuff_const,aes_const)                    \
    v2 = _mm_aeskeygenassist_si128(v4,aes_const);                           \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                        _mm_castsi128_ps(v1), 16));        \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                        _mm_castsi128_ps(v1), 140));       \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v2 = _mm_shuffle_epi32(v2,shuff_const);                                 \
    v1 = _mm_xor_si128(v1,v2)


void AES_128_Key_Expansion(const unsigned char *userkey, void *key)
{
    __m128i x0,x1,x2;
    __m128i *kp = (__m128i *)key;
    kp[0] = x0 = _mm_loadu_si128((__m128i*)userkey);
    x2 = _mm_setzero_si128();
    EXPAND_ASSIST(x0,x1,x2,x0,255,1);   kp[1]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,2);   kp[2]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,4);   kp[3]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,8);   kp[4]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,16);  kp[5]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,32);  kp[6]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,64);  kp[7]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,128); kp[8]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,27);  kp[9]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,54);  kp[10] = x0;
}

static inline __m128i AES_Encrypt_rounds(__m128i tmp, __m128i *key, int rounds){
        int j;
        tmp = _mm_xor_si128 (tmp,key[0]);
        for (j=1; j<rounds; j++){
            tmp = _mm_aesenc_si128 (tmp,key[j]);
        }  
        tmp = _mm_aesenclast_si128 (tmp,key[j]);
        return tmp;
    }


int main(int argc, char const *argv[]){
    
    ALIGN (16) char plaintext[MESSAGE_LENGHT];
    ALIGN (16) unsigned char ciphertext[MESSAGE_LENGHT];
    for (size_t i = 0; i < MESSAGE_LENGHT; i++){
        plaintext[i] = 0x2a;
        ciphertext[i] = 0;
    }
    
    unsigned char key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    long unsigned int period=0;

    __m128i pt = _mm_load_si128 ((__m128i*)&plaintext[0] );
    __m128i K = _mm_load_si128 ((__m128i*)&key[0] );
    __m128i ct = _mm_setzero_si128(); 

    __m128i roundKeys[11];
    AES_128_Key_Expansion(key, roundKeys);
    K = AES_Encrypt_rounds(K,roundKeys,10);

    print_hex_string((unsigned char *)&pt,16 );
    print_hex_string((unsigned char *)&K,16 );
    printf("---------------------------------------------\n");

    serach_period_point(pt, ct, K);


    
    return 0;
}


// Retorna true si v1 es idéntico a v2
int is_equal(__m128i v1, __m128i v2) {
    __m128i diff = _mm_xor_si128(v1, v2);
    return _mm_test_all_zeros(diff, diff); // PTEST: retorna 1 si todo es cero
}

int serach_period_point(__m128i pt,__m128i ct, __m128i key ){
    long unsigned int period=0;
    bool condition = 1;

    do 
    {

        ct = _mm_aesenc_si128 (pt,key);
        period++;
        if (is_equal(pt,ct)){

            condition=0;
        }
        if ((period  == __UINT16_MAX__) ){
            printf("__UINT16_MAX__ %lu\n", period);
            fflush(stdout); // Forzado de impresión inmediata
        }

        if ((period==__UINT32_MAX__)){
            printf("__UINT32_MAX__ %lu",period);
            fflush(stdout); // Forzado de impresión inmediata
        }
        if ((period==1099511627776) ){
            printf("1099511627776 %lu",period);
            fflush(stdout); // Forzado de impresión inmediata
        }
        
        
    }while (condition);
    
    printf("Plaintext:");
    print_hex_string((unsigned char *)&pt,16 );
    printf("Ciphertext:");
    print_hex_string((unsigned char *)&ct,16 );
    printf("key:");
    print_hex_string((unsigned char *)&key,16 );
    printf("Periodo %li ",period);

    return period;
}

void counter_mode(unsigned char plaintext[],unsigned char N[],unsigned char key[],int size, unsigned char ciphertext[] ){

    __m128i roundKeys[11];
    AES_128_Key_Expansion(key, roundKeys);

    __m128i nonce;
    nonce = _mm_load_si128 ((__m128i*)&N[0] );
    nonce = AES_Encrypt_rounds(nonce,roundKeys,10);

    __m128i high_part = _mm_set_epi32(0xffffffff,0xffffffff,0,0);
    nonce = _mm_and_si128(nonce,high_part);
    
    __m128i counter = _mm_set_epi32(0,0,0,1);
    
    int num_blocks = 1;
    if (size%16==0)
        num_blocks=size/16;
    else
        num_blocks=(size/16)+1;

    __m128i * pt;
    pt = (__m128i *)plaintext;

    __m128i ct[num_blocks];

    for (size_t i = 0; i < num_blocks; i++){
        
        __m128i temp = AES_Encrypt_rounds(nonce,roundKeys,10);
        
        ct[i]= _mm_xor_si128(temp,pt[i]); 
        nonce = _mm_add_epi64(nonce,counter);

    }
    

    for (size_t i = 0; i < num_blocks; i++)
    {
        _mm_store_si128 ((__m128i*)ciphertext+i, ct[i]);
    }
    

}


void chaining_block_cipher_MAC(unsigned char plaintext[],unsigned char N[],unsigned char key[],unsigned char T[],int size ){

    __m128i roundKeys[11];
    AES_128_Key_Expansion(key, roundKeys);

    __m128i nonce;
    nonce = _mm_load_si128 ((__m128i*)&N[0] );

    nonce = AES_Encrypt_rounds(nonce,roundKeys,10);
    
    int num_blocks = 1;
    if (size%16==0)
        num_blocks=size/16;
    else
        num_blocks=(size/16)+1;

    __m128i * pt;
    pt = (__m128i *)plaintext;


    __m128i tag = nonce;

    for (size_t i = 0; i < num_blocks; i++){
        tag = _mm_xor_si128(pt[i],tag); 
        tag = AES_Encrypt_rounds(tag ,roundKeys,10);
    }
    _mm_store_si128 ((__m128i*)T, tag);

}



void print_hex_string(unsigned char* buf, int len)
{
    int i;

    if (len==0) { printf("<empty string>"); return; }
    if (len>=40 ) {
        for (i = 0; i < 10; i++)
             printf("%02x", *((unsigned char *)buf + i));
        printf(" ... ");
        for (i = len-10; i < len; i++)
             printf("%02x", *((unsigned char *)buf + i));
        printf(" [%d bytes]", len);
        printf("\n");
        return;
    }
    for (i = 0; i < len; i++){
        if( i%4==0 ){
            printf(" ");
        }
        printf("%02x", *((unsigned char *)buf + i));
        
    }
    printf("\n");

}