#define  _CRT_SECURE_NO_WARNINGS
#include "miracl.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#pragma comment(lib,"miracl.lib")

//char *primetext="155315526351482395991155996351231807220169644828378937433223838972232518351958838087073321845624756550146945246003790108045940383194773439496051917019892370102341378990113959561895891019716873290512815434724157588460613638202017020672756091067223336194394910765309830876066246480156617492164140095427773547319";
char* text = "";
time_t begin, end;

int main()
{
    /*
        加解密
    */
    big a, b, p, q, n, p1, q1, phi, pa, pb, key, e, d, dp, dq, t, m, c;
    big primes[2], pm[2];
    big_chinese ch;
    long l = 12;
    long cum = 0;
    miracl* mip;
    char input[256];
#ifndef MR_NOFULLWIDTH   
    mip = mirsys(100, 0);
#else
    mip = mirsys(100, MAXBASE);
#endif
    a = mirvar(0);
    b = mirvar(0);
    p = mirvar(0);
    q = mirvar(0);
    n = mirvar(0);
    p1 = mirvar(0);
    q1 = mirvar(0);
    phi = mirvar(0);
    pa = mirvar(0);
    pb = mirvar(0);
    e = mirvar(0);
    d = mirvar(0);
    dp = mirvar(0);
    dq = mirvar(0);
    t = mirvar(0);
    m = mirvar(0);
    c = mirvar(0);
    pm[0] = mirvar(0);
    pm[1] = mirvar(0);
    printf("*******************RSA加、解密程序*******************\n\n");

    printf("\n1、密钥生成\n");
    do
    {
        bigbits(l, p);
        if (subdivisible(p, 2)) incr(p, 1, p);
        while (!isprime(p)) incr(p, 2, p);

        bigbits(l, q);
        if (subdivisible(q, 2)) incr(q, 1, q);
        while (!isprime(q)) incr(q, 2, q);

        multiply(p, q, n);      /* n=p.q */

        lgconv(65537L, e);
        decr(p, 1, p1);
        decr(q, 1, q1);
        multiply(p1, q1, phi);  /* phi =(p-1)*(q-1) */
    } while (xgcd(e, phi, d, d, t) != 1);
    printf("p=");
    cotnum(p, stdout);
    printf("q=");
    cotnum(q, stdout);
    printf("n = p*q =");
    cotnum(n, stdout);
    printf("phi =(p-1)*(q-1)=");
    cotnum(phi, stdout);

    /* set up for chinese remainder thereom */
    primes[0] = p;
    primes[1] = q;
    crt_init(&ch, 2, primes);
    copy(d, dp);
    copy(d, dq);
    divide(dp, p1, p1);   /* dp=d mod p-1 */
    divide(dq, q1, q1);   /* dq=d mod q-1 */


    printf("\n\n2、加密\n");
    printf("输入明文：");
    scanf("%s", input);
    text = input;
    mip->IOBASE = l;
    cinstr(m, text);
    mip->IOBASE = 10;
    begin = clock();
    while (cum < 10000)
    {
        powmod(m, e, n, c);
        cum++;
    }
    printf("密文为：");
    cotnum(c, stdout);
    end = clock();
    printf("加密时间: %f seconds\n", (double)(end - begin) / CLOCKS_PER_SEC);
    zero(m);

    printf("\n\n3、解密\n");
    begin = clock();
    powmod(c, dp, p, pm[0]);    /* get result mod p */
    powmod(c, dq, q, pm[1]);    /* get result mod q */
    crt(&ch, pm, m);           /* combine them using CRT */

    printf("明文为：");
    mip->IOBASE = l;
    cotnum(m, stdout);
    crt_end(&ch);
    end = clock();
    printf("解密时间: %f seconds\n\n", (double)(end - begin) / CLOCKS_PER_SEC);
    system("pause");
    return 0;
}