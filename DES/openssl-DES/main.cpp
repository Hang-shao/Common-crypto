#include <iostream>
#include "openssl/des.h"

using namespace std;
/*
 * DES-ECBģʽ�ӽ��ܲ���
 */
int main() {
    //����
    unsigned char data[]="1234567";
    //��Կ
    unsigned char key[]="abcdefg";
    //����
    unsigned char cip[]={0};
    //���
    unsigned char out[]={0};
    DES_key_schedule key_sch; //ʵ�ʴ洢��Կ

    //��Կ����
    DES_set_key((const_DES_cblock*)&key,&key_sch);
    //����
    DES_ecb_encrypt((const_DES_cblock*)&data,(DES_cblock*)&cip,&key_sch,DES_ENCRYPT);
    cout << "���ģ�"<<cip<<endl;
    //����
    DES_ecb_encrypt((const_DES_cblock*)&cip,(DES_cblock*)&out,&key_sch,DES_DECRYPT);
    cout << "���ģ�" <<out<<endl;

    return 0;
}
