#include <iostream>
#include "paillier.h"

using namespace std;
using namespace NTL;

ZZ lcm(ZZ x, ZZ y){
  ZZ ans = (x * y) / NTL::GCD(x,y);
  return ans;
}

int main()
{
    ZZ p = ZZ(43);
    ZZ q = ZZ(41);
    ZZ lambda = lcm(p - 1, q - 1);
    Paillier paillier(p*q, lambda);
    ZZ n = p * q;

    cout << "p = " << p << endl;
    cout << "q = " << q << endl;
    cout << "n = " << n << endl;
    //generator=lambda+1
    cout << "lamdba = " << lambda << endl;

    cout << "------------加解密测试------------"<<endl;
    ZZ m = ZZ(100); //明文消息
    ZZ c = paillier.encrypt(m);
    cout << "m = "<<m<< ", c = " << c << endl;
    ZZ m_ = paillier.decrypt(c);
    cout << "m2 = " << m_ << endl;
    if (m == m_){
        cout << "m = m2, encryption and decryption successful" << endl;
    }

    cout << "------------同态性测试------------"<<endl;
    ZZ m1 = ZZ(100); //明文消息
    ZZ m2 = ZZ(8);
    ZZ c1 = paillier.encrypt(m1, (ZZ)131 );
    ZZ c2 = paillier.encrypt(m2, (ZZ)223 );
    cout << "m1 = "<<m1<<", c1 = " << c1 << endl;
    cout << "m2 = "<<m1<<", c2 = " << c2 << endl;

    ZZ c_add=paillier.hom_add(c1,c2);
    ZZ c_add_const=paillier.hom_add_const(c1,m2);
    ZZ c_mult=paillier.hom_mult(c1,m2);

    ZZ m_add = paillier.decrypt(c_add);
    ZZ m_add_const = paillier.decrypt(c_add_const);
    ZZ m_mult = paillier.decrypt(c_mult);

    cout << "m_add = " << m_add << endl;
    cout << "m_add_const = " << m_add_const << endl;
    cout << "m_mult = " << m_mult << endl;
    return 0;
}