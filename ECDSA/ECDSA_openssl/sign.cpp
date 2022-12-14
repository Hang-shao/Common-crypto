#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>

#define SIGN   "static unsigned char signature[%d] = {"
#define ENDKEY   "\n};\n"
#define MAXSIGLEN  128

/* 私钥数据 */   static unsigned char privkey[279] = {
    0x30, 0x82, 0x01, 0x13, 0x02, 0x01, 0x01, 0x04,
    0x20, 0xE8, 0x01, 0x44, 0xD9, 0x98, 0x71, 0x41,
    0x54, 0x2B, 0x4D, 0xDF, 0x50, 0x7E, 0x4D, 0xB3,
    0xCA, 0x5F, 0x30, 0x39, 0xA0, 0x51, 0x82, 0x76,
    0x39, 0xFF, 0xC4, 0x63, 0x38, 0x0E, 0xDB, 0x2A,
    0xB9, 0xA0, 0x81, 0xA5, 0x30, 0x81, 0xA2, 0x02,
    0x01, 0x01, 0x30, 0x2C, 0x06, 0x07, 0x2A, 0x86,
    0x48, 0xCE, 0x3D, 0x01, 0x01, 0x02, 0x21, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
    0x30, 0x06, 0x04, 0x01, 0x00, 0x04, 0x01, 0x07,
    0x04, 0x41, 0x04, 0x79, 0xBE, 0x66, 0x7E, 0xF9,
    0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE,
    0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D,
    0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
    0xF8, 0x17, 0x98, 0x48, 0x3A, 0xDA, 0x77, 0x26,
    0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E,
    0x11, 0x08, 0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6,
    0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB,
    0x10, 0xD4, 0xB8, 0x02, 0x21, 0x00, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE,
    0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2,
    0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41, 0x02, 0x01,
    0x01, 0xA1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x68,
    0x45, 0x28, 0xB0, 0x36, 0xEA, 0x02, 0x46, 0x0A,
    0x4E, 0x24, 0x43, 0x28, 0x97, 0x61, 0xC5, 0xE0,
    0x30, 0xE7, 0xAE, 0x79, 0x5A, 0xFE, 0x27, 0x9D,
    0xF2, 0x76, 0xD8, 0xAC, 0x97, 0x6E, 0x1C, 0x73,
    0x6E, 0x42, 0x40, 0x36, 0x00, 0x8A, 0x01, 0x2D,
    0xBD, 0xF2, 0x9A, 0x68, 0x83, 0x24, 0xA1, 0x6F,
    0x77, 0xD0, 0x4E, 0xE1, 0x2D, 0x07, 0x33, 0xE6,
    0xCE, 0x24, 0x61, 0xAE, 0xF3, 0xCB, 0x38 };


    /* 签名函数 */
static unsigned int sign(unsigned char *sig,const unsigned char *buf,int len)
{
    unsigned int sign_len = MAXSIGLEN;
    EC_KEY *ec_key = NULL;
    unsigned char *pp = (unsigned char*)privkey;

    /* 导入私钥 */
    ec_key = d2i_ECPrivateKey(&ec_key, (const unsigned char**)&pp, sizeof(privkey));
    memset(privkey,0,sizeof(privkey));
    if ( ec_key == NULL){
        printf("Error：d2i_ECPrivateKey()\n");
        return -1;
    }

    /* 数据签名 */
    if (!ECDSA_sign(0,buf, len, sig,&sign_len,ec_key)) {
        printf("Error：ECDSA_sign()\n");
        EC_KEY_free(ec_key);
        return -1;
    }


    EC_KEY_free(ec_key);
    return sign_len;
}

/* 主函数 */
int main(int argc, char* argv[])
{
    const char message[] = "wangdali";
    unsigned char *signature,digest[32]={};
    unsigned int  dgst_len = 0;
    
    EVP_MD_CTX md_ctx;  
    EVP_MD_CTX_init(&md_ctx);
    EVP_DigestInit(&md_ctx, EVP_sha256());

    // 散列算法
    EVP_DigestUpdate(&md_ctx, (const void*)message,sizeof(message));
    EVP_DigestFinal(&md_ctx, digest, &dgst_len);
    signature=(unsigned char *)malloc(MAXSIGLEN);
    int len = sign(signature,(unsigned char*)&digest,dgst_len);
    int i=0;
    printf(SIGN,len);

    for (i=0; i<len; i++){
        if ( !(i % 8) )
            printf("\n");
        if(i==len-1)
            printf("0x%02X ",signature[i]);
        else
            printf("0x%02X, ",signature[i]);
    }

    printf(ENDKEY);
    return 0;
}