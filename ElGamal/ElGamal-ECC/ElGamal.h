#pragma once
#include <iostream>
#include <algorithm>

using namespace std;

typedef  struct Point{
    int x;
    int y;
};
class ELGama {
public:
    ELGama(int p, int a, int b);

    int unEqLamda(Point A, Point B);

    int equalLamda(Point A);

    Point equalELGama(Point A, int lamda);

    Point unEqELGama(Point A, Point B, int lamda);

    Point kPcal(Point A, int k);

    Point PplusQcal(Point A, Point B);

    Point add_Reverse(Point A);

private:
    int p, a, b;
    //calculate s and t in s * a + t * b = gcd(a, b)
    void STgcd(int a, int b, int& s, int& t);
};

Point ELGama::PplusQcal(Point A, Point B) {
    int lamda = unEqLamda(A,B);
    return unEqELGama(A,B,lamda);
}

Point ELGama::kPcal(Point A, int k) {
    int lamda;
    Point R={-1,-1};
    while (k) {
        Point T;
        T.x = A.x, T.y = A.y;
        if (k & 1) {
            if (R.x == -1 && R.y == -1) {
                R.x = T.x;
                R.y = T.y;
            }
            else {
                lamda = unEqLamda(T, R);
                R=unEqELGama(T, R, lamda);
            }
        }

        lamda = equalLamda(T);
        A=equalELGama(T, lamda);
        k >>= 1;
    }
    return  R;
}

Point ELGama::equalELGama(Point A, int lamda) {
    Point R;
    R.x = ((lamda * lamda - 2 * A.x) % p + p) % p;
    R.y = ((lamda * (A.x - R.x) - A.y) % p + p) % p;
    return  R;
}

Point ELGama::unEqELGama(Point A,Point B, int lamda) {
    Point R;
    R.x = ((lamda * lamda -A.x -B.x) % p + p) % p;
    R.y = ((lamda * (A.x - R.x) - A.y) % p + p) % p;
    return  R;
}

ELGama::ELGama(int pl, int al, int bl) {
    p = pl;
    a = al;
    b = bl;
}

int ELGama::unEqLamda(Point A,Point B) {
    int s, t, up = ((B.y - A.y) % p + p) % p, down = ((B.x - A.x) % p + p) % p;
    STgcd(down, p, s, t);
    return (s + p) * up % p;
}

int ELGama::equalLamda(Point A) {
    int s, t, up = ((3 * A.x * A.x + a) % p + p) % p, down = ((A.y * 2) % p + p) % p;
    STgcd(down, p, s, t);
    return (s % p + p) * up % p;
}

//calculate s and t in s * a + t * b = gcd(a, b)
void ELGama::STgcd(int a, int b, int& s, int& t)
{
    int s1, t1;
    if (b == 0)
    {
        s = a;
        t = b;
    }
    else
    {
        STgcd(b, a % b, s, t);
        s1 = s;
        t1 = t;
        s = t1;
        t = s1 - a / b * t1;
    }
}

//求加法逆元
Point add_Reverse(Point A){
    Point R;
    R.x=A.x;
    R.y=-A.y;
    return  R;
}