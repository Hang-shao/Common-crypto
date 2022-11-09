#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>

#define MAXSIGLEN  128

/* 公钥 */
static const unsigned char pubkey[65] = {
    0x04, 0x68, 0x45, 0x28, 0xB0, 0x36, 0xEA, 0x02,
    0x46, 0x0A, 0x4E, 0x24, 0x43, 0x28, 0x97, 0x61,
    0xC5, 0xE0, 0x30, 0xE7, 0xAE, 0x79, 0x5A, 0xFE,
    0x27, 0x9D, 0xF2, 0x76, 0xD8, 0xAC, 0x97, 0x6E,
    0x1C, 0x73, 0x6E, 0x42, 0x40, 0x36, 0x00, 0x8A,
    0x01, 0x2D, 0xBD, 0xF2, 0x9A, 0x68, 0x83, 0x24,
    0xA1, 0x6F, 0x77, 0xD0, 0x4E, 0xE1, 0x2D, 0x07,
    0x33, 0xE6, 0xCE, 0x24, 0x61, 0xAE, 0xF3, 0xCB,
    0x38
};

/* 验证函数 */
static int verify(const unsigned char *sig,int siglen,const unsigned char *buf,int buflen)
{
    int ret;
    EC_KEY *ec_key = NULL;
    EC_GROUP *ec_group;
    unsigned char *pp = (unsigned char*)pubkey;
    if ((ec_key = EC_KEY_new()) == NULL)  {
        printf("Error：EC_KEY_new()\n");   return -1;
    }

    if ((ec_group = EC_GROUP_new_by_curve_name(NID_secp256k1)) == NULL)  {
        printf("Error：EC_GROUP_new_by_curve_name()\n");
        EC_KEY_free(ec_key);
        return -1;
    }

    /* 设置密钥参数 */
    ret=EC_KEY_set_group(ec_key,ec_group);
    if(ret!=1){
        printf("Error：EC_KEY_set_group\n");
        EC_KEY_free(ec_key);
        return -1;
    }

    /* 导入公钥 */
    ec_key = o2i_ECPublicKey(&ec_key,(const unsigned char**)&pp,sizeof(pubkey));
    if (ec_key == NULL)  {
        printf("Error：o2i_ECPublicKey\n");
        EC_KEY_free(ec_key);
        return 0;
    }
    
    /* 验证签名 */
    ret = ECDSA_verify(0,(const unsigned char*)buf, buflen, sig, siglen,ec_key); 
    EC_KEY_free(ec_key);
    return ret == 1 ? 1 : 0;
}

/* 主函数 */
int main(int argc, char* argv[])
{
    const char message[] = "wangdali";
    unsigned char digest[32]={};
    unsigned int  dgst_len = 0;
    
    EVP_MD_CTX md_ctx;  
    EVP_MD_CTX_init(&md_ctx);
    EVP_DigestInit(&md_ctx, EVP_sha256()); 
    
    // 散列算法  
    EVP_DigestUpdate(&md_ctx, (const void*)message,sizeof(message));
    EVP_DigestFinal(&md_ctx, digest, &dgst_len);
    static unsigned char signature[72] = {
        0x30, 0x46, 0x02, 0x21, 0x00, 0xC4, 0x2D, 0xE1,
        0x99, 0xC4, 0xF4, 0xA5, 0x91, 0x14, 0x63, 0x06,
        0x75, 0xCC, 0x72, 0xBC, 0x1F, 0x8B, 0xA4, 0x4B,
        0x68, 0x78, 0xCF, 0xBB, 0xE2, 0xCD, 0x39, 0xE0,
        0xA9, 0xE2, 0xC8, 0xBA, 0xB7, 0x02, 0x21, 0x00,
        0xE7, 0x6E, 0x45, 0x2C, 0x1B, 0x71, 0x8F, 0xE5,
        0x9E, 0xA3, 0x65, 0xF8, 0x22, 0xD8, 0x1F, 0xA7,
        0x3C, 0x08, 0x62, 0x57, 0x33, 0xD5, 0xE8, 0x08,
        0xD0, 0xC2, 0x85, 0x50, 0xEA, 0x48, 0x7A, 0xD7
    };

    int ret = verify((const unsigned char *)&signature,sizeof(signature),(const unsigned char *)&digest,dgst_len);
    if(ret==1)  {
        printf("Verify：OK\n");
    }else{
        printf("Verify：Error\n");
    }

    return 0;
}