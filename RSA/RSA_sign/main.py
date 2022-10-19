import random

import math


# 快速幂取模

def power(a, b, n):  # 计算a**b mod n

    if b == 0:

        return 1  # 如果b值为0则返回1

    elif b % 2 == 0:  # 如果二进制b最后一位为0

        p = power(a, b / 2, n)  # 递归实现

        return (p * p) % n  # 取模运算

    else:

        return (a * power(a, b - 1, n)) % n  # 返回结果


# 欧几里得算法求最大公约数

def gcd(a, b):
    if a < b:

        return gcd(b, a)  # 如果a小于b，交换两个数

    elif a % b == 0:

        return b  # 如果a整除于b则返回b

    else:

        return gcd(b, a % b)  # 递归实现欧几里得算法


# 确定是否是素数

def isPrime(num):
    if (num < 2):

        return False  # 如果num的值小于2返回false

    else:

        i = 2

        flag = True

        while i < num:  # 如果num能被i整除，说明num不是质数

            if num % i == 0:
                flag = False  # 只要num不是质数，将flag的值修改为 False

            i += 1

        return flag  # 最后返回flag的值


# 生成大素数函数

def randPrime(n):
    Start = 10 ** (n - 1)  # n的值为5，计算开始值10**4

    End = (10 ** n) - 1  # 计算结束10**5-1

    while True:

        num = random.randint(Start, End)  # 返回从start到end之间任意一个数表示大素数

        if isPrime(num):  # 判断是否是质数，如果是则生成

            return num  # 返回大素数的值num


# 扩展的欧几里得算法，即ab=1 (mod n), 得到a在模n下的乘法逆元b

def Extended_Eulid(a, n):
    x1, x2, x3 = 1, 0, n

    y1, y2, y3 = 0, 1, a

    while y3 != 1 and y3 != 0 and y3 > 0:
        Q = math.floor(x3 / y3)

        t1, t2, t3 = x1 - Q * y1, x2 - Q * y2, x3 - Q * y3

        x1, x2, x3 = y1, y2, y3

        y1, y2, y3 = t1, t2, t3

    if y3 == 0:
        return 0

    if y3 == 1:

        if y2 > 0:

            return y2

        else:

            return n + y2


# 生成公钥和私钥

def KeyGen(p, q):  # 分别计算n，e，d的值

    n = p * q

    e = random.randint(1, (p - 1) * (q - 1))

    while gcd(e, (p - 1) * (q - 1)) != 1:  # 运用欧几里得算法判断

        e = random.randint(1, (p - 1) * (q - 1))

    d = Extended_Eulid(e, (p - 1) * (q - 1))

    return n, e, d


# 利用快速幂取模计算签名

def Sign(x, d, n):
    s = power(x, d, n)

    return s


# 利用快速幂取模判断是否有效签名

def Verify(s, e, n):
    x_ = power(s, e, n)

    return x_


# 主函数

if __name__ == '__main__':

    key_size = 5

    p = randPrime(key_size)  # p与q分别为随机生成的大素数

    q = randPrime(key_size)

    n, e, d = KeyGen(p, q)  # 用p与q生成公钥和私钥

    # 输入消息

    x = int(input("请输入加密信息（必须为整数）: "))

    # 计算签名

    s = Sign(x, d, n)

    # 验证签名

    x_ = Verify(s, e, n)

    Valid = (x_ == x)

    # 输出

    print("私钥: ")

    print("N: ", n)

    print("d: ", d)

    print("公钥: ")

    print("N: ", n)

    print("e: ", e)

    print("签名: ")

    print("s: ", s)

    print("验证m的签名: ",x_)

    if Valid:

        print("签名有效!")

    else:

        print("签名无效!")