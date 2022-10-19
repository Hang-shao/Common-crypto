#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#define randomInt(a,b) (rand()%(b-a)+a)//生成[a,b]之间的随机数

//是否为素数
int prime(int n)
{
    int i;
    if (n < 2) {
        return -1;
    }
    else {
        for (i = 2; i < n; i++) {//判断n在2~n-1中有没有因数
            if (n % i == 0)//如果用可以除尽的数,则非素数
                break;
        }
        if (i < n) {//存在2~n-1之间有因数
            return -1;
        }
        else
            return 0;
    }
    return 0;
}
//素数生成
int creat_Prime(int a,int b)
{
    int res,k;
    srand((unsigned)time(NULL));
    do
    {
        res = randomInt(a, b);
        k = prime(res);
    } while (k == -1);
    return res;
}

//求最大公约数，判断两个数是否互素
int gcd(int x, int y)
{
    int t;
    while (y) t = x, x = y, y = t % y;
    return x;
}

//扩展欧几里得算法 （C++实现）
int exgcd(int a, int b, int &x, int &y)
{
    if (b == 0)
    {
        x = 1, y = 0;
        return a;
    }
    int ret = exgcd(b, a % b, y, x);
    y -= a / b * x;
    return ret;
}

//求逆元：基于费马定理
int reverse(int a, int mod)
{
    int x, y;
    int d = exgcd(a, mod, x, y);
    return d == 1 ? (x % mod + mod) % mod : -1;
}

//快速幂模（a^b mod p)
int power(int a, int b, int p)
{
    int ans = 1 % p;
    while(b)
    {
        if(b & 1)
        {
            ans = ans * a % p;
        }
        b >>= 1;
        a = a * a % p;
    }
    return ans;
}

//加密算法测试
void encrypt_test()
{
    printf("\n------------RSA加密算法------------\n");

    printf("\n\t    1、密钥生成\n");
    //p和q是大素数;n=pq;z=(p-1)(q-1);任取e，使满足gcd(e,z)=1;d是e的逆;m是明文;c是密文;m1是解密后明文
    int p, q, n, z, e, d, m, c, m1;

    //随机生成p和q

    p = creat_Prime(1, 5);
    q = creat_Prime(5, 10);
    /*
    printf("请输入p：");
    scanf("%d", &p);
    printf("请输入q：");
    scanf("%d", &q);
    */

    //求n和z
    n = q * p;
    z = (p - 1) * (q - 1);

    //随机生成e：e和z互素，e < n

    do
    {
        e = creat_Prime(1, n);
    } while (gcd(e, z) != 1);

    /*
    printf("请输入e：");
    scanf("%d", &e);
    */

    //求d：d是e的逆元，mod z
    d = reverse(e, z);

    printf("p=%d\nq=%d\nn=%d\nz=%d\ne=%d\nd=%d\n", p,q,n,z,e,d);

    //输出公私钥
    printf("公钥为：{n,e}={%d,%d}\n", n, e);
    printf("私钥为：{d}={%d}\n", d);

    printf("\n\t    2、加密\n");

    //明文生成\输入
    printf("请输入明文m：");
    scanf("%d",&m);

    //加密
    c = power(m,e,n);

    printf("明文为：{m}={%d}\n", m);
    printf("密文为：{c}={%d}\n", c);

    printf("\n\t    3、解密\n");
    //解密
    m1 =power(c,d,n);
    printf("解密后明文：{m1}={%d}\n\n", m1);
}

//乘法同态测试
void mult_test()
{
    printf("\n------------RSA乘法同态------------\n");

    printf("\n\t    1、密钥生成\n");
    //p和q是大素数;n=pq;z=(p-1)(q-1);任取e，使满足gcd(e,z)=1;d是e的逆;m是明文;c是密文;m1是解密后明文
    int p, q, n, z, e, d, m_1,m_2,c_1,c_2,m,c;

    //随机生成p和q

    p = creat_Prime(1, 5);
    q = creat_Prime(5, 10);
    /*
    printf("请输入p：");
    scanf("%d", &p);
    printf("请输入q：");
    scanf("%d", &q);
    */

    //求n和z
    n = q * p;
    z = (p - 1) * (q - 1);

    //随机生成e：e和z互素，e < n

    do
    {
        e = creat_Prime(1, n);
    } while (gcd(e, z) != 1);

    /*
    printf("请输入e：");
    scanf("%d", &e);
    */

    //求d：d是e的逆元，mod z
    d = reverse(e, z);

    printf("p=%d\nq=%d\nn=%d\nz=%d\ne=%d\nd=%d\n", p,q,n,z,e,d);

    //输出公私钥
    printf("公钥为：{n,e}={%d,%d}\n", n, e);
    printf("私钥为：{d}={%d}\n", d);

    printf("\n\t    2、加密\n");

    //明文生成\输入
    printf("请输入明文m1：");
    scanf("%d",&m_1);
    printf("请输入明文m2：");
    scanf("%d",&m_2);
    //加密
    c_1 = power(m_1,e,n);
    c_2 =  power(m_2,e,n);
    printf("明文为：{m_1}={%d},{m_2}={%d}\n", m_1,m_2);
    printf("密文为：{c_1}={%d},{c_2}={%d}\n", c_1,c_2);

    printf("\n\t    3、乘法同态\n");
    //乘法同态
    c=c_1*c_2%n;
    printf("密文乘为：{c_1*c_2}={%d}\n",c);

    printf("\n\t    4、解密\n");
    //解密
    m = power(c,d,n);
    printf("解密后明文：{m_1*m_2}={%d}\n\n", m);
}

int main()
{
    int choose;
    printf("请输入序号：【1】加解密测试，【2】乘法同态性测试\n");
    scanf("%d",&choose);
    if(choose ==1)
    {
        //加解密测试
        encrypt_test();
    }else if(choose ==2)
    {
        //乘法同态性测试
        mult_test();
    }else
        printf("请重新输入！");
    system("pause");
    return 0;
}