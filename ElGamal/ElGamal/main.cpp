/*
 * ElGamal算法实现
 * 功能：加解密、乘法同态
 */
#include<iostream>
#include<cstdio>
#define randomInt(a,b) (rand()%(b-a)+a) //生成指定范围的随机数
using namespace std;
typedef long long ll;
typedef struct C{
    ll c_1;
    ll c_2;
};

ll p,a,x,y,r,m1,m2;
C c1,c2,c3;

ll qpow(ll r, ll n, ll mod){//计算a^n % mod
    ll re = 1;
    while(n){
        if(n & 1)
            re = (re * r) % mod;
        n >>= 1;
        r = (r * r) % mod;
    }
    return re % mod;
}

ll byy(ll lp){//求Zlp*的生成元
    bool flag;
    for(ll i=2;i<lp;i++){
        flag=true;
        for(ll j=2;j<lp-1;j++){
            if((lp-1)%j==0){
                if(qpow(i,j,lp)==1) flag=false;
            }
        }
        if(flag) return i;
    }
}

ll inv(ll la, ll lp){//求逆元——扩展欧几里得算法
    if(la == 1) return 1;
    return inv(lp%la,lp)*(lp-lp/la)%lp;
}

C encode(ll la,ll lp,ll ly,ll lm){
    C c;
    printf("\n======加密======\n");
    ll lr=randomInt(1,lp-1);
    printf("随机数r=%lld\n",lr);
    c.c_1=qpow(la,lr,lp);
    c.c_2=(lm*qpow(ly,lr,lp))%lp;
    printf("得到的密文为c_1=%lld   c_2=%lld\n",c.c_1,c.c_2);
    return c;
}

void decode(ll lx,ll lp,C c){
    printf("\n======解密======\n");
    c.c_1=qpow(c.c_1,lx,lp);
    c.c_1=inv(c.c_1,lp);
    ll m=(c.c_1*c.c_2)%lp;
    printf("得到的明文为m=%lld\n",m);
}

C mult_c(ll lp,C lc1,C lc2){ //同态乘法
    C c;
    printf("\n======同态乘法======\n");
    c.c_1=(lc1.c_1*lc2.c_1)%lp;
    c.c_2=(lc1.c_2*lc2.c_2)%lp;
    printf("密文相乘后c_1=%lld   c_2=%lld\n",c.c_1,c.c_2);
    return c;
}

int main(){
    printf("请输入参数p:");
    scanf("%lld",&p);
    a=byy(p);
    printf("计算出本原元a=%lld   \n",a);
    printf("\n======密钥生成======\n");
    x=randomInt(1,p-1);
    y=qpow(a,x,p);
    printf("公钥pk={%lld,%lld,%lld}，私钥sk={%lld}\n",p,a,y,x);
    printf("测试加解密，输入1；测试乘法同态，输入2\n");
    int choose;
    scanf("%d",&choose);
    if(choose==1)
    {
        printf("请输入要加密的明文m：");
        scanf("%lld",&m1);
        c1=encode(a,p,y,m1);  //加密
        decode(x,p,c1);  //解密
    }else if(choose==2)
    {
        printf("请输入要加密的明文m1和m2：");
        scanf("%lld%lld",&m1,&m2);
        c1=encode(a,p,y,m1);  //加密m1
        c2=encode(a,p,y,m2);  //加密m2
        c3= mult_c(p,c1,c2);
        decode(x,p,c3);  //解密c3
        printf("验证结果m1*m2=%lld\n",m1*m2%p);
    }else
        printf("选择错误，请重新选择！\n");
    return 0;
}
