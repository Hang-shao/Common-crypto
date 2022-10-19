#include <iostream>
#include "openssl/des.h"

using namespace std;
/*
 * DES-ECB模式加解密测试
 */
int main() {
    //明文
    unsigned char data[]="1234567";
    //密钥
    unsigned char key[]="abcdefg";
    //密文
    unsigned char cip[]={0};
    //输出
    unsigned char out[]={0};
    DES_key_schedule key_sch; //实际存储密钥

    //密钥生成
    DES_set_key((const_DES_cblock*)&key,&key_sch);
    //加密
    DES_ecb_encrypt((const_DES_cblock*)&data,(DES_cblock*)&cip,&key_sch,DES_ENCRYPT);
    cout << "密文："<<cip<<endl;
    //解密
    DES_ecb_encrypt((const_DES_cblock*)&cip,(DES_cblock*)&out,&key_sch,DES_DECRYPT);
    cout << "明文：" <<out<<endl;

    return 0;
}
