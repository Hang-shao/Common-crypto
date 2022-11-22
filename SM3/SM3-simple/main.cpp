#include <iostream>
#include <string>
#include <cmath>
using namespace std;

//二进制转换为十六进制函数实现
string BinToHex(string str) {
    string hex = "";//用来存储最后生成的十六进制数
    int temp = 0;//用来存储每次四位二进制数的十进制值
    while (str.size() % 4 != 0) {//因为每四位二进制数就能够成为一个十六进制数，所以将二进制数长度转换为4的倍数
        str = "0" + str;//最高位添0直到长度为4的倍数即可
    }
    for (int i = 0; i < str.size(); i += 4) {
        temp = (str[i] - '0') * 8 + (str[i + 1] - '0') * 4 + (str[i + 2] - '0') * 2 + (str[i + 3] - '0') * 1;//判断出4位二进制数的十进制大小为多少
        if (temp < 10) {//当得到的值小于10时，可以直接用0-9来代替
            hex += to_string(temp);
        }
        else {//当得到的值大于10时，需要进行A-F的转换
            hex += 'A' + (temp - 10);
        }
    }
    return hex;
}

//十六进制转换为二进制函数实现
string HexToBin(string str) {
    string bin = "";
    string table[16] = { "0000","0001","0010","0011","0100","0101","0110","0111","1000","1001","1010","1011","1100","1101","1110","1111" };
    for (int i = 0; i < str.size(); i++) {
        if (str[i] >= 'A'&&str[i] <= 'F') {
            bin += table[str[i] - 'A' + 10];
        }
        else {
            bin += table[str[i] - '0'];
        }
    }
    return bin;
}

//二进制转换为十进制的函数实现
int BinToDec(string str) {
    int dec = 0;
    for (int i = 0; i < str.size(); i++) {
        dec += (str[i] - '0')*pow(2, str.size() - i - 1);
    }
    return dec;
}

//十进制转换为二进制的函数实现
string DecToBin(int str) {
    string bin = "";
    while (str >= 1) {
        bin = to_string(str % 2) + bin;
        str = str / 2;
    }
    return bin;
}

//十六进制转换为十进制的函数实现
int HexToDec(string str) {
    int dec = 0;
    for (int i = 0; i < str.size(); i++) {
        if (str[i] >= 'A'&&str[i] <= 'F') {
            dec += (str[i] - 'A' + 10)*pow(16, str.size() - i - 1);
        }
        else {
            dec += (str[i] - '0')*pow(16, str.size() - i - 1);
        }
    }
    return dec;
}

//十进制转换为十六进制的函数实现
string DecToHex(int str) {
    string hex = "";
    int temp = 0;
    while (str >= 1) {
        temp = str % 16;
        if (temp < 10 && temp >= 0) {
            hex = to_string(temp) + hex;
        }
        else {
            hex += ('A' + (temp - 10));
        }
        str = str / 16;
    }
    return hex;
}

string padding(string str) {//对数据进行填充
    string res = "";
    for (int i = 0; i < str.size(); i++) {//首先将输入值转换为16进制字符串
        res += DecToHex((int)str[i]);
    }
    cout << "输入字符串的ASCII码表示为：" << endl;
    for (int i = 0; i < res.size(); i++) {
        cout << res[i];
        if ((i + 1) % 8 == 0) {
            cout << "  ";
        }
        if ((i + 1) % 64 == 0 || (i + 1) == res.size()) {
            cout << endl;
        }
    }
    cout << endl;
    //填充方式：先补加1，然后填充0至112位，最后16bit填充0+原来长度（二进制）
    int res_length = res.size() * 4;//记录的长度为2进制下的长度
    res += "8";//在获得的数据后面添1，在16进制下相当于是添加8
    while (res.size() % 128 != 112) {
        res += "0";//“0”数据填充
    }
    string res_len = DecToHex(res_length);//用于记录数据长度的字符串
    while (res_len.size() != 16) {
        res_len = "0" + res_len;
    }
    res += res_len;
    return res;
}

string LeftShift(string str, int len) {//实现循环左移len位功能
    string res = HexToBin(str);
    res = res.substr(len) + res.substr(0, len);
    return BinToHex(res);
}

string XOR(string str1, string str2) {//实现异或操作
    string res1 = HexToBin(str1);
    string res2 = HexToBin(str2);
    string res = "";
    for (int i = 0; i < res1.size(); i++) {
        if (res1[i] == res2[i]) {
            res += "0";
        }
        else {
            res += "1";
        }
    }
    return BinToHex(res);
}

string AND(string str1, string str2) {//实现与操作
    string res1 = HexToBin(str1);
    string res2 = HexToBin(str2);
    string res = "";
    for (int i = 0; i < res1.size(); i++) {
        if (res1[i] == '1' && res2[i] == '1') {
            res += "1";
        }
        else {
            res += "0";
        }
    }
    return BinToHex(res);
}

string OR(string str1, string str2) {//实现或操作
    string res1 = HexToBin(str1);
    string res2 = HexToBin(str2);
    string res = "";
    for (int i = 0; i < res1.size(); i++) {
        if (res1[i] == '0' && res2[i] == '0') {
            res += "0";
        }
        else {
            res += "1";
        }
    }
    return BinToHex(res);
}

string NOT(string str) {//实现非操作
    string res1 = HexToBin(str);
    string res = "";
    for (int i = 0; i < res1.size(); i++) {
        if (res1[i] == '0') {
            res += "1";
        }
        else {
            res += "0";
        }
    }
    return BinToHex(res);
}

char binXor (char str1, char str2) {//实现单比特的异或操作
    return str1 == str2 ? '0' : '1';
}

char binAnd(char str1, char str2) {//实现单比特的与操作
    return (str1 == '1'&&str2 == '1') ? '1' : '0';
}

string ModAdd(string str1, string str2) {//mod 2^32运算的函数实现
    string res1 = HexToBin(str1);
    string res2 = HexToBin(str2);
    char temp = '0';
    string res = "";
    for (int i = res1.size() - 1; i >= 0; i--) {
        res = binXor(binXor(res1[i], res2[i]), temp) + res;
        if (binAnd(res1[i], res2[i]) == '1') {
            temp = '1';
        }
        else {
            if (binXor(res1[i], res2[i]) == '1') {
                temp = binAnd('1', temp);
            }
            else {
                temp = '0';
            }
        }
    }
    return BinToHex(res);
}

string P1(string str) {//实现置换功能P1（X）
    return XOR(XOR(str, LeftShift(str, 15)), LeftShift(str, 23));
}

string P0(string str) {//实现置换功能P0（X）
    return XOR(XOR(str, LeftShift(str, 9)), LeftShift(str, 17));
}

string T(int j) {//返回Tj常量值的函数实现
    if (0 <= j && j <= 15) {
        return "79CC4519";
    }
    else {
        return "7A879D8A";
    }
}

string FF(string str1, string str2, string str3, int j) {//实现布尔函数FF功能
    if (0 <= j && j <= 15) {
        return XOR(XOR(str1, str2), str3);
    }
    else {
        return OR(OR(AND(str1, str2), AND(str1, str3)), AND(str2, str3));
    }
}

string GG(string str1, string str2, string str3, int j) {//实现布尔函数GG功能
    if (0 <= j && j <= 15) {
        return XOR(XOR(str1, str2), str3);
    }
    else {
        return OR(AND(str1, str2), AND(NOT(str1), str3));
    }
}
string extension(string str) {//消息扩展函数
    string res = str;//字符串类型存储前68位存储扩展字W值
    for (int i = 16; i < 68; i++) {//根据公式生成第17位到第68位的W值
        res += XOR(
                XOR(
                        P1(
                                XOR(
                                        XOR(
                                                res.substr((i-16)*8,8), res.substr((i - 9) * 8, 8)),
                                                LeftShift(res.substr((i - 3) * 8, 8), 15)
                                        )
                                ),
                    LeftShift(res.substr((i - 13) * 8, 8), 7)
                        ),
            res.substr((i - 6) * 8, 8));
    }
    cout << "扩展后的消息：" << endl;
    cout << "W0,W1,……,W67的消息：" << endl;
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            cout << res.substr(i * 64 + j * 8, 8) << "  ";
        }
        cout << endl;
    }
    cout << res.substr(512, 8) << "  " << res.substr(520, 8) << "  " << res.substr(528, 8) << "  " << res.substr(536, 8) << endl;
    cout << endl;
    for (int i = 0; i < 64; i++) {//根据公式生成64位W'值
        res += XOR(res.substr(i * 8, 8), res.substr((i + 4) * 8, 8));
    }
    cout << "W0',W1',……,W63'的消息：" << endl;
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            cout << res.substr(544+i * 64 + j * 8, 8) << "  ";
        }
        cout << endl;
    }
    cout << endl;
    return res;
}

string compress(string str1, string str2) {//消息压缩函数
    string IV = str2;
    string A = IV.substr(0, 8), B = IV.substr(8, 8), C = IV.substr(16, 8), D = IV.substr(24, 8), E = IV.substr(32, 8), F = IV.substr(40, 8), G = IV.substr(48, 8), H = IV.substr(56, 8);
    string SS1 = "", SS2 = "", TT1 = "", TT2 = "";
    cout << "迭代压缩中间值: " << endl;
    cout << "    A         B         C         D         E         F        G         H " << endl;
    cout << A << "  " << B << "  " << C << "  " << D << "  " << E << "  " << F << "  " << G << "  " << H << endl;
    for (int j = 0; j < 64; j++) {
        SS1 = LeftShift(ModAdd(ModAdd(LeftShift(A, 12), E), LeftShift(T(j), (j%32))), 7);
        SS2 = XOR(SS1, LeftShift(A, 12));
        TT1 = ModAdd(ModAdd(ModAdd(FF(A, B, C, j), D), SS2), str1.substr((j + 68) * 8, 8));
        TT2 = ModAdd(ModAdd(ModAdd(GG(E, F, G, j), H), SS1), str1.substr(j * 8, 8));
        D = C;
        C = LeftShift(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = LeftShift(F, 19);
        F = E;
        E = P0(TT2);
        cout << A << "  " << B << "  " << C << "  " << D << "  " << E << "  " << F << "  " << G << "  " << H << endl;
    }
    string res = (A + B + C + D + E + F + G + H);
    cout << endl;
    return res;
}

string iteration(string str) {//迭代压缩函数实现
    int num = str.size() / 128; //求有多少分组
    cout << "消息经过填充之后共有 " + to_string(num) + " 个消息分组。" << endl;
    cout << endl;
    string V = "7380166F4914B2B9172442D7DA8A0600A96F30BC163138AAE38DEE4DB0FB0E4E"; //初始IV（256bit）
    string B = "", extensionB = "", compressB = "";
    for (int i = 0; i < num; i++) {
        cout << "第 " << to_string(i+1) << " 个消息分组：" << endl;
        cout << endl;
        B = str.substr(i * 128, 128);//取一个分组（512bit）
        extensionB = extension(B); //密钥扩展，得到132个字
        compressB = compress(extensionB, V); //压缩函数，返回的是ABCDEFGH
        V = XOR(V, compressB); //V^{i+1}=V^{i} ^ V ^{i}
    }
    return V;
}

int main() {//主函数
    string str[2];
    str[0] = "abc";
    str[1] = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    for (int num = 0; num < 2; num++) {
        //to_string()：将数字常量转换为字符串，返回值为转换后的字符串
        cout << "示例 " + to_string(num + 1) + " ：输入消息为字符串: " + str[num] << endl;
        cout << endl;
        string paddingValue = padding(str[num]);
        cout << "填充后的消息为：" << endl;
        for (int i = 0; i < paddingValue.size() / 64; i++) {
            for (int j = 0; j < 8; j++) {
                //substr(pos,len)：从初始位置pos开始读取长度为len个字符
                cout << paddingValue.substr(i * 64 + j * 8, 8) << "  ";
            }
            cout << endl;
        }
        cout << endl;
        string result = iteration(paddingValue);
        cout << "杂凑值：" << endl;
        for (int i = 0; i < 8; i++) {
            cout << result.substr(i * 8, 8) << "  ";
        }
        cout << endl;
        cout << endl;
    }
}