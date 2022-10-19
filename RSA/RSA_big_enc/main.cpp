#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#define randomInt(a,b) (rand()%(b-a)+a)//����[a,b]֮��������

//�Ƿ�Ϊ����
int prime(int n)
{
    int i;
    if (n < 2) {
        return -1;
    }
    else {
        for (i = 2; i < n; i++) {//�ж�n��2~n-1����û������
            if (n % i == 0)//����ÿ��Գ�������,�������
                break;
        }
        if (i < n) {//����2~n-1֮��������
            return -1;
        }
        else
            return 0;
    }
    return 0;
}
//��������
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

//�����Լ�����ж��������Ƿ���
int gcd(int x, int y)
{
    int t;
    while (y) t = x, x = y, y = t % y;
    return x;
}

//��չŷ������㷨 ��C++ʵ�֣�
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

//����Ԫ�����ڷ�����
int reverse(int a, int mod)
{
    int x, y;
    int d = exgcd(a, mod, x, y);
    return d == 1 ? (x % mod + mod) % mod : -1;
}

//������ģ��a^b mod p)
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

//�����㷨����
void encrypt_test()
{
    printf("\n------------RSA�����㷨------------\n");

    printf("\n\t    1����Կ����\n");
    //p��q�Ǵ�����;n=pq;z=(p-1)(q-1);��ȡe��ʹ����gcd(e,z)=1;d��e����;m������;c������;m1�ǽ��ܺ�����
    int p, q, n, z, e, d, m, c, m1;

    //�������p��q

    p = creat_Prime(1, 5);
    q = creat_Prime(5, 10);
    /*
    printf("������p��");
    scanf("%d", &p);
    printf("������q��");
    scanf("%d", &q);
    */

    //��n��z
    n = q * p;
    z = (p - 1) * (q - 1);

    //�������e��e��z���أ�e < n

    do
    {
        e = creat_Prime(1, n);
    } while (gcd(e, z) != 1);

    /*
    printf("������e��");
    scanf("%d", &e);
    */

    //��d��d��e����Ԫ��mod z
    d = reverse(e, z);

    printf("p=%d\nq=%d\nn=%d\nz=%d\ne=%d\nd=%d\n", p,q,n,z,e,d);

    //�����˽Կ
    printf("��ԿΪ��{n,e}={%d,%d}\n", n, e);
    printf("˽ԿΪ��{d}={%d}\n", d);

    printf("\n\t    2������\n");

    //��������\����
    printf("����������m��");
    scanf("%d",&m);

    //����
    c = power(m,e,n);

    printf("����Ϊ��{m}={%d}\n", m);
    printf("����Ϊ��{c}={%d}\n", c);

    printf("\n\t    3������\n");
    //����
    m1 =power(c,d,n);
    printf("���ܺ����ģ�{m1}={%d}\n\n", m1);
}

//�˷�̬ͬ����
void mult_test()
{
    printf("\n------------RSA�˷�̬ͬ------------\n");

    printf("\n\t    1����Կ����\n");
    //p��q�Ǵ�����;n=pq;z=(p-1)(q-1);��ȡe��ʹ����gcd(e,z)=1;d��e����;m������;c������;m1�ǽ��ܺ�����
    int p, q, n, z, e, d, m_1,m_2,c_1,c_2,m,c;

    //�������p��q

    p = creat_Prime(1, 5);
    q = creat_Prime(5, 10);
    /*
    printf("������p��");
    scanf("%d", &p);
    printf("������q��");
    scanf("%d", &q);
    */

    //��n��z
    n = q * p;
    z = (p - 1) * (q - 1);

    //�������e��e��z���أ�e < n

    do
    {
        e = creat_Prime(1, n);
    } while (gcd(e, z) != 1);

    /*
    printf("������e��");
    scanf("%d", &e);
    */

    //��d��d��e����Ԫ��mod z
    d = reverse(e, z);

    printf("p=%d\nq=%d\nn=%d\nz=%d\ne=%d\nd=%d\n", p,q,n,z,e,d);

    //�����˽Կ
    printf("��ԿΪ��{n,e}={%d,%d}\n", n, e);
    printf("˽ԿΪ��{d}={%d}\n", d);

    printf("\n\t    2������\n");

    //��������\����
    printf("����������m1��");
    scanf("%d",&m_1);
    printf("����������m2��");
    scanf("%d",&m_2);
    //����
    c_1 = power(m_1,e,n);
    c_2 =  power(m_2,e,n);
    printf("����Ϊ��{m_1}={%d},{m_2}={%d}\n", m_1,m_2);
    printf("����Ϊ��{c_1}={%d},{c_2}={%d}\n", c_1,c_2);

    printf("\n\t    3���˷�̬ͬ\n");
    //�˷�̬ͬ
    c=c_1*c_2%n;
    printf("���ĳ�Ϊ��{c_1*c_2}={%d}\n",c);

    printf("\n\t    4������\n");
    //����
    m = power(c,d,n);
    printf("���ܺ����ģ�{m_1*m_2}={%d}\n\n", m);
}

int main()
{
    int choose;
    printf("��������ţ���1���ӽ��ܲ��ԣ���2���˷�̬ͬ�Բ���\n");
    scanf("%d",&choose);
    if(choose ==1)
    {
        //�ӽ��ܲ���
        encrypt_test();
    }else if(choose ==2)
    {
        //�˷�̬ͬ�Բ���
        mult_test();
    }else
        printf("���������룡");
    system("pause");
    return 0;
}