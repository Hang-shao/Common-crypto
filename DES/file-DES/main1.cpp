#include <iostream>
#include <openssl/des.h>
#include <fstream>
using namespace std;

int main(int argc, char* argv[]) {
    string cmd = "加密文件： crypt_file 输入文件名 输出文件名 密码（6）\n";
    cmd += "解密文件：crypt_file 输入文件名 输出文件名 密码（6） -d\n";
    cout << cmd << endl;
    if (argc < 4) {
        cerr << "para error" << endl;
        return -1;
    }
    string in_file = argv[1];       //输入文件
    string out_file = argv[2];      //输出文件
    string password = argv[3];      //秘钥
    int is_encrypt = DES_ENCRYPT;   //加密
    if (argc > 4)
        is_encrypt = DES_DECRYPT;   //解密

    //二进制打开输入文件
    ifstream ifs(in_file, ios::binary);
    if (!ifs) {
        cerr << "in_file:" << in_file << " open failed!" << endl;
        return -1;
    }

    //二进制打开输出文件
    ofstream ofs(out_file, ios::binary);
    if (!ofs) {
        ifs.close();
        cerr << "out_file:" << out_file << " open failed!" << endl;
        return -1;
    }

    //处理秘钥 多出丢掉，少的补0
    int key_size = password.size();
    const_DES_cblock key = {0}; //少的补0
    if (key_size > sizeof(key))
        key_size = sizeof(key); //多出丢掉
    memcpy(key, password.c_str(), key_size);
    DES_key_schedule key_sch;
    DES_set_key(&key, &key_sch);    //设置秘钥

    const_DES_cblock in; //输入数据
    DES_cblock out;      //输出数据

    //获取文件大小
    long long filesize = 0;
    ifs.seekg(0, ios::end);//文件指针移到结尾
    filesize = ifs.tellg();
    ifs.seekg(0, ios::beg);
    cout << "filesize = " << filesize << endl;
    long long read_size = 0;
    long long write_size = 0;

    //1读文件 =》2加解密文件 =》3写入文件
    while (!ifs.eof()) {
        //每次写入字节大小
        int out_len = sizeof(out);

        //1 读文件
        ifs.read((char *) in, sizeof(in));
        int count = ifs.gcount();
        if (count <= 0)break;
        read_size += count;

        //PKCS7 Padding 填充
        //加密到结尾处 填充
        if (read_size == filesize && is_encrypt == DES_ENCRYPT) {
            if (filesize % 8 == 0)  //填充8字节的值为8
            {
                //先写入当前数据
                DES_ecb_encrypt(&in, &out, &key_sch, is_encrypt);
                ofs.write((char *) out, out_len);

                //填充数据 8
                memset(in, 8, sizeof(in));
            } else {
                int padding = 8 - filesize % 8;//要填充的字节
                //移到位置填充数据
                memset(in + (filesize % 8), padding, padding);
            }
        }

        //2 加解密文件
        DES_ecb_encrypt(&in, &out, &key_sch, is_encrypt);

        //解密结尾处padding
        if (read_size == filesize && is_encrypt == DES_DECRYPT) {
            //减去填充大小
            out_len = 8 - out[7];
        }
        if (out_len <= 0)break;

        //3 写入文件
        ofs.write((char *) out, out_len);
        write_size += out_len;
    }
    ifs.close();
    ofs.close();
    cout << "write :" << write_size << endl;

    return 0;
}