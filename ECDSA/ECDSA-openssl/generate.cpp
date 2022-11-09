#include <stdio.h> 
#include <openssl/crypto.h> 
#include <openssl/evp.h> 
#include <openssl/ecdsa.h>

#define PRIVKEY "static unsigned char privkey[%d]={" 
#define PUBKEY "static const unsigned char pubkey[%d]={" 
#define ENDKEY "\n};\n"

int main(int argc, char *argv[])
{ 
    EC_KEY *ec_key; 
    EC_GROUP *ec_group; 
    unsigned char buf[1024]; 
    unsigned char *pp;  
    int i, len; 
     
    if((ec_key = EC_KEY_new()) == NULL) {
       printf("Error：EC_KEY_new()\n"); 
       return 0; 
    } 

   /*选择一条椭圆曲线*/
    if((ec_group = EC_GROUP_new_by_curve_name(NID_secp256k1)) == NULL) {
        printf("Error：EC_GROUP_new_by_curve_name()\n"); 
        EC_KEY_free(ec_key); 
        return -1; 
    }

    /*设置密钥参数*/
    int ret;
    ret = EC_KEY_set_group(ec_key,ec_group); 
    if(ret != 1) {
        printf("Error：EC_KEY_set_group()\n"); 
        return -1;
    }

    /*生成密钥对*/
    if(!EC_KEY_generate_key(ec_key)) { 
        printf("Error：EC_KEY_generate_key()\n"); 
        EC_KEY_free(ec_key); 
        return -1;
    }

    /*导出私钥*/ 
    pp = buf;
    len = i2d_ECPrivateKey(ec_key,&pp);  
    if(!len) {
        printf("Error：i2d_ECPrivateKey()\n");
        EC_KEY_free(ec_key); 
        return -1;
    }

    printf(PRIVKEY,len); 
    for(i=0;i<len;i++)  {
        if(!(i%8))  
            printf("\n"); 
        if(i==len-1)
            printf("0x%02X",buf[i]); 
        else
            printf("0x%02X,",buf[i]); 
    }
    printf(ENDKEY);

    /*导出公钥*/ 
    pp=buf; 
    len=i2o_ECPublicKey(ec_key,&pp); 
    if(!len){
        printf("Error：i2o_ECPublicKey()\n"); 
        EC_KEY_free(ec_key);
        return-1;
    }

    printf(PUBKEY,len); 
    for(i=0;i<len;i++)  {
        if(!(i%8))  
            printf("\n"); 
        if(i==len-1)
            printf("0x%02X",buf[i]); 
        else
            printf("0x%02X,",buf[i]); 
    }
    printf(ENDKEY); 

    EC_KEY_free(ec_key); 
    return 0; 
}
