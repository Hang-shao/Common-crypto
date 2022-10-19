#include "ElGamal.h"
//代码：https://github.com/ProbeTS/Cryptography/tree/master/ELGama

int main() {
    int p=751,a=-1,b=188;
    ELGama* e = new ELGama(p, a, b);
    //生成元
    Point G={0,376};
    //密钥
    int n_A=58; //私钥
    Point P_A=e->kPcal(G, n_A); //公钥
    //加密
    Point P_m={562,201};
    int k=386;
    Point c1=e->kPcal(G, k);
    Point c2=e->PplusQcal(P_m,e->kPcal(P_A, k));
    cout <<"密文：{("<<c1.x<<","<<c1.y<<"),("<<c2.x<<","<<c2.y<<")}"<< endl;
    //解密
    Point M=e->PplusQcal(c2, add_Reverse(e->kPcal(c1,n_A)));
    cout <<"("<<M.x<<","<<M.y<<")"<< endl;
    return 0;
}