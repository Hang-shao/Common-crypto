#include <iostream>
#include <iomanip>
#include "AES.h"

using namespace std;
void enc_Test()
{
    int choose=0;
    cout<<endl<<"加解密测试-选择："
          "1：AES-128bit-10轮；"
          "2：AES-192bit-12轮"
          "3：AES-256bit-14轮"<<endl;
    cin>>choose;
    const unsigned int BLOCK_BYTES_LENGTH = 16 * sizeof(unsigned char);
    if(choose==1)
    {
        cout<<"-----------------------------AES-128bit-10轮-----------------------------"<<endl;
        AES aes(AESKeyLength::AES_128);
        cout<<"明文：";
        unsigned char plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
        for(int i=0;i<16;i++)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)plain[i]<<" ";

        cout<<endl<<"密钥：";
        unsigned char key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        for(int i=0;i<16;i++)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)key[i]<<" ";

        cout<<endl<<"加密后：";
        unsigned char *cip = aes.EncryptECB(plain, BLOCK_BYTES_LENGTH, key);
        for(int i=0;i<16;i++)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)cip[i]<<" ";

        cout<<endl<<"解密后：";
        unsigned char *out = aes.DecryptECB(cip,BLOCK_BYTES_LENGTH, key);
        for(int i=0;i<16;i++)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)out[i]<<" ";
    } else if(choose==2)
    {
        cout<<"-----------------------------AES-192bit-12轮-----------------------------"<<endl;
        const unsigned int BLOCK_BYTES_LENGTH = 16 * sizeof(unsigned char);
        AES aes(AESKeyLength::AES_192);
        cout<<"明文：";
        unsigned char plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
        for(int i=0;i<16;i++)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)plain[i]<<" ";

        cout<<endl<<"密钥：";
        unsigned char key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
        for(int i=0;i<24;i++)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)key[i]<<" ";

        cout<<endl<<"加密后：";
        unsigned char *cip = aes.EncryptECB(plain, BLOCK_BYTES_LENGTH, key);
        for(int i=0;i<16;i++)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)cip[i]<<" ";

        cout<<endl<<"解密后：";
        unsigned char *out = aes.DecryptECB(cip,BLOCK_BYTES_LENGTH, key);
        for(int i=0;i<16;i++)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)out[i]<<" ";
    }else if(choose==3)
    {
        cout<<"-----------------------------AES-256bit-14轮-----------------------------"<<endl;
        const unsigned int BLOCK_BYTES_LENGTH = 16 * sizeof(unsigned char);
        AES aes(AESKeyLength::AES_256);
        cout<<"明文：";
        unsigned char plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
        for(int i=0;i<16;i++)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)plain[i]<<" ";

        cout<<endl<<"密钥：";
        unsigned char key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                               0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
        for(int i=0;i<32;i++)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)key[i]<<" ";

        cout<<endl<<"加密后：";
        unsigned char *cip = aes.EncryptECB(plain, BLOCK_BYTES_LENGTH, key);
        for(int i=0;i<16;i++)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)cip[i]<<" ";

        cout<<endl<<"解密后：";
        unsigned char *out = aes.DecryptECB(cip,BLOCK_BYTES_LENGTH, key);
        for(int i=0;i<16;i++)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)out[i]<<" ";
    }else
        cout<<"输入错误！"<<endl;
}

//模式测试
void modles_Test()
{
    int choose=0;
    cout<<endl<<"分组模式测试-选择："
          "1：AES-ECB-128bit；"
          "2：AES-CBC-128bit"
          "3：AES-CFB-128bit"<<endl;
    cin>>choose;
    const unsigned int BLOCK_BYTES_LENGTH = 16 * sizeof(unsigned char);
    if(choose==1)
    {
        cout<<"-----------------------------AES-ECB-128bit-----------------------------"<<endl;
        AES aes(AESKeyLength::AES_128);
        cout<<"明文：";
        vector<unsigned char> plain = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                            0xcc, 0xdd, 0xee, 0xff};
        for(auto i:plain)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)i<<" ";

        cout<<endl<<"密钥：";
        vector<unsigned char> key = {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        for(auto i:key)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)i<<" ";

        cout<<endl<<"加密后：";
        vector<unsigned char> cip = aes.EncryptECB(plain, key);
        for(auto i:cip)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)i<<" ";

        cout<<endl<<"解密后：";
        vector<unsigned char> out = aes.DecryptECB(cip, key);
        for(auto i:out)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)i<<" ";
    } else if(choose==2)
    {
        cout<<"-----------------------------AES-CBC-128bit-----------------------------"<<endl;
        AES aes(AESKeyLength::AES_128);
        cout<<"明文：";
        vector<unsigned char> plain = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                            0xcc, 0xdd, 0xee, 0xff};
        for(auto i:plain)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)i<<" ";

        vector<unsigned char> iv = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                         0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                         0xff, 0xff, 0xff, 0xff};   //初始化向量
        cout<<endl<<"密钥：";
        vector<unsigned char> key = {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        for(auto i:key)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)i<<" ";

        cout<<endl<<"加密后：";
        vector<unsigned char> cip = aes.EncryptCBC(plain, key, iv);
        for(auto i:cip)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)i<<" ";

        cout<<endl<<"解密后：";
        vector<unsigned char> out = aes.DecryptCBC(cip, key, iv);
        for(auto i:out)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)i<<" ";
    }else if(choose==3)
    {
        cout<<"-----------------------------AES-CFB-128bit-----------------------------"<<endl;
        AES aes(AESKeyLength::AES_128);
        cout<<"明文：";
        vector<unsigned char> plain = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                            0xcc, 0xdd, 0xee, 0xff};
        for(auto i:plain)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)i<<" ";

        vector<unsigned char> iv = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                         0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                         0xff, 0xff, 0xff, 0xff};       //初始化向量
        cout<<endl<<"密钥：";
        vector<unsigned char> key = {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        for(auto i:key)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)i<<" ";

        cout<<endl<<"加密后：";
        vector<unsigned char> cip = aes.EncryptCFB(plain, key, iv);
        for(auto i:cip)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)i<<" ";

        cout<<endl<<"解密后：";
        vector<unsigned char> out = aes.DecryptCFB(cip, key, iv);
        for(auto i:out)
            cout<<setfill('0')<<setw(2)<<hex<<(unsigned int)i<<" ";
    }else
        cout<<"输入错误！"<<endl;
}
int main() {

    enc_Test();
    cout<<endl;
    modles_Test();

    return 0;
}
