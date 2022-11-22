#include "zuc.h"

unsigned int AddMod(unsigned int a, unsigned int b)
{
    unsigned int c = a + b;
    if (c >> 31)
    {
        c = (c & 0x7fffffff) + 1;
    }
    return c;
}


unsigned int PowMod(unsigned int x, unsigned int k)
{
    return (((x << k) | (x >> (31 - k))) & 0x7fffffff);
}


unsigned int L1(unsigned int X)
{
    return X ^ ZUC_rotl32(X, 2) ^ ZUC_rotl32(X, 10) ^ ZUC_rotl32(X, 18) ^ ZUC_rotl32(X, 24);
}
unsigned int L2(unsigned int X)
{
    return X ^ ZUC_rotl32(X, 8) ^ ZUC_rotl32(X, 14) ^ ZUC_rotl32(X, 22) ^ ZUC_rotl32(X, 30);
}

unsigned char BitValue(unsigned int M[], unsigned int i)
{
    int j, k;
    j = i >> 5;
    k = i & 0x1f;
    if (M[j] & (0x1 << (31 - k)))
        return 1;
    else
        return 0;
}

unsigned int GetWord(unsigned int k[], unsigned int i)             //获取字串中的从第i个比特值开始的字
{
    int j, m;
    unsigned int word;
    j = i >> 5;
    m = i & 0x1f;
    if (m == 0)
        word = k[j];
    else
        word = (k[j] << m) | (k[j + 1] >> (32 - m));
    return word;
}
void LFSRWithInitMode(unsigned int LFSR_S[], unsigned int u)
{
    unsigned int v = LFSR_S[0], i;
    v = AddMod(v, PowMod(LFSR_S[15], 15));
    v = AddMod(v, PowMod(LFSR_S[13], 17));
    v = AddMod(v, PowMod(LFSR_S[10], 21));
    v = AddMod(v, PowMod(LFSR_S[4], 20));
    v = AddMod(v, PowMod(LFSR_S[0], 8));

    for (i = 0; i < 15; i++)
    {
        LFSR_S[i] = LFSR_S[i + 1];
    }
    LFSR_S[15] = AddMod(v, u);

    if (!LFSR_S[15])
    {
        LFSR_S[15] = 0x7fffffff;
    }
}

void LFSRWithWorkMode(unsigned int LFSR_S[])
{
    unsigned int v = LFSR_S[0], i;
    v = AddMod(v, PowMod(LFSR_S[15], 15));
    v = AddMod(v, PowMod(LFSR_S[13], 17));
    v = AddMod(v, PowMod(LFSR_S[10], 21));
    v = AddMod(v, PowMod(LFSR_S[4], 20));
    v = AddMod(v, PowMod(LFSR_S[0], 8));

    for (i = 0; i < 15; i++)
    {
        LFSR_S[i] = LFSR_S[i + 1];
    }
    LFSR_S[15] = v;

    if (!LFSR_S[15])
    {
        LFSR_S[15] = 0x7fffffff;
    }
}

void BR(unsigned int LFSR_S[], unsigned int BR_X[])
{
    BR_X[0] = ((LFSR_S[15] & 0x7fff8000) << 1) | (LFSR_S[14] & 0x0000ffff);
    BR_X[1] = ((LFSR_S[11] & 0x0000ffff) << 16) | ((LFSR_S[9] & 0x7fff8000) >> 15);
    BR_X[2] = ((LFSR_S[7] & 0x0000ffff) << 16) | ((LFSR_S[5] & 0x7fff8000) >> 15);
    BR_X[3] = ((LFSR_S[2] & 0x0000ffff) << 16) | ((LFSR_S[0] & 0x7fff8000) >> 15);
}

unsigned int F(unsigned int BR_X[], unsigned int F_R[])
{
    unsigned int W, W1, W2;

    W = (BR_X[0] ^ F_R[0]) + F_R[1];
    W1 = F_R[0] + BR_X[1];
    W2 = F_R[1] ^ BR_X[2];
    F_R[0] = L1((W1 << 16) | (W2 >> 16));
    F_R[0] = (ZUC_S0[(F_R[0] >> 24) & 0xFF]) << 24 | (ZUC_S1[(F_R[0] >> 16) & 0xFF]) << 16 | (ZUC_S0[(F_R[0] >> 8) & 0xFF]) << 8 | (ZUC_S1[F_R[0] & 0xFF]);
    F_R[1] = L2((W2 << 16) | (W1 >> 16));
    F_R[1] = (ZUC_S0[(F_R[1] >> 24) & 0xFF]) << 24 | (ZUC_S1[(F_R[1] >> 16) & 0xFF]) << 16  | (ZUC_S0[(F_R[1] >> 8) & 0xFF]) << 8 | (ZUC_S1[F_R[1] & 0xFF]);

    return W;
}

void ZUC_Init(unsigned int k[], unsigned int iv[], unsigned int LFSR_S[], unsigned int BR_X[], unsigned int F_R[])
{
    unsigned char count = 32;
    int i;

    //loading key to the LFSR s0,s1,s2....s15
    printf("\ninitial state of LFSR: S[0]-S[15]\n");
    for (i = 0; i < 16; i++)
    {
        printf("i=%d,k=%08x,ZUC_d=%08x,iv=%08x\n",i,k[i],ZUC_d[i],iv[i]);
        LFSR_S[i] = ZUC_LinkToS(k[i], ZUC_d[i], iv[i]);
        printf("%08x  \n", LFSR_S[i]);
    }

    F_R[0] = 0x00;    //R1
    F_R[1] = 0x00;    //R2

    // 初始变量和秘钥状态完毕后，开始32轮初始化
    while (count)         //32 times
    {
        unsigned int W;
        BR(LFSR_S, BR_X); //BitReconstruction
        printf("count=%d,BR={%d,%d,%d,%d}\n",count,BR_X[0],BR_X[1],BR_X[2],BR_X[3]);
        W = F(BR_X, F_R);   //nonlinear function
        LFSRWithInitMode(LFSR_S, W >> 1);
        count--;
    }
}

void ZUC_Work(unsigned int LFSR_S[], unsigned int BR_X[], unsigned int F_R[], unsigned int pKeyStream[], int KeyStreamLen)
{
    int i = 0;
    BR(LFSR_S, BR_X);
    F(BR_X, F_R);
    LFSRWithWorkMode(LFSR_S);
    printf("------------------------------------------------------------\n输出密钥流：\n");
    while (i < KeyStreamLen)
    {
        BR(LFSR_S, BR_X);
        pKeyStream[i] = F(BR_X, F_R) ^ BR_X[3];
        printf("pKeyStream[%d]=%08x\n", i,pKeyStream[i]);
        LFSRWithWorkMode(LFSR_S);
        i++;
    }
}

//密钥流生成
void ZUC_GenKeyStream(unsigned int k[], unsigned int iv[], unsigned int KeyStream[], int KeyStreamLen)
{

    unsigned int LFSR_S[16]; //LFSR state s0,s1,s2,...s15
    unsigned int BR_X[4];    //Bit Reconstruction X0,X1,X2,X3
    unsigned int F_R[2];     //R1,R2,variables of nonlinear function F
    int i;

    for(int i=0;i<16;i++)
    {
        printf("iv[%d]=%08x\n",i,iv[i]);
    }

    //Initialisation
    ZUC_Init(k, iv, LFSR_S, BR_X, F_R);
    printf("\n------------------------------------------------------------\nstate of LFSR after executing initialization: S[0]-S[15]\n");
    for (i = 0; i < 16; i++)
    {
        printf("%08x  ", LFSR_S[i]);
    }
    printf("\n------------------------------------------------------------\ninternal state of Finite State Machine:\n");
    printf("R1=%08x\n", F_R[0]);
    printf("R2=%08x\n", F_R[1]);

    //Working
    ZUC_Work(LFSR_S, BR_X, F_R, KeyStream, KeyStreamLen);
}

//机密性
void ZUC_Confidentiality(unsigned char CK[], unsigned int COUNT, unsigned char BEARER,unsigned char DIRECTION,unsigned int IBS[],int LENGTH,unsigned int OBS[])
{
    unsigned int *k;
    int L,i,t;
    unsigned char iv[16];
    //generate vector iv1,iv2,...iv15
    iv[0] = (unsigned char)(COUNT >> 24);
    iv[1] = (unsigned char)((COUNT >> 16) & 0xff);
    iv[2] = (unsigned char)((COUNT >> 8) & 0xff);
    iv[3] = (unsigned char)(COUNT & 0xff);
    iv[4] = (((BEARER << 3) | (DIRECTION << 2)) & 0xfc);
    iv[5] = 0x00;
    iv[6] = 0x00;
    iv[7] = 0x00;
    iv[8] = iv[0];
    iv[9] = iv[1];
    iv[10] = iv[2];
    iv[11] = iv[3];
    iv[12] = iv[4];
    iv[13] = iv[5];
    iv[14] = iv[6];
    iv[15] = iv[7];


    //L,the length of key stream,taking 32bit as a unit
    L = (LENGTH + 31) / 32;
    k=malloc(sizeof(unsigned int)*L);
    //generate key stream k
    ZUC_GenKeyStream(CK, iv, k, L); //generate key stream
    //OBS=IBS^k
    for(i = 0; i < L; i++)
    {
        OBS[i] = IBS[i] ^ k[i]; //明文和密钥流异或
    }
    t = LENGTH % 32;
    if(t)
    {
        OBS[L-1] = ((OBS[L-1] >> (32-t)) << (32-t));
    }
    free(k);
}

//完整性
unsigned int ZUC_Integrity(unsigned char IK[],unsigned int COUNT,unsigned char BEARER,unsigned char DIRECTION,unsigned int M[],int LENGTH)
{
    unsigned int *k, ki,MAC;
    int L,i;
    unsigned char iv[16];
    unsigned int T = 0;
    //generate vector iv1,iv2,...iv15
    iv[0] = (unsigned char)(COUNT >> 24);
    iv[1] = (unsigned char)((COUNT >> 16) & 0xff);
    iv[2] = (unsigned char)((COUNT >> 8) & 0xff);
    iv[3] = (unsigned char)(COUNT & 0xff);
    iv[4] = BEARER << 3;
    iv[5] = 0x00;
    iv[6] = 0x00;
    iv[7] = 0x00;
    iv[8] = iv[0] ^ (DIRECTION << 7);
    iv[9] = iv[1];
    iv[10] = iv[2];
    iv[11] = iv[3];
    iv[12] = iv[4];
    iv[13] = iv[5];
    iv[14] = iv[6]^ (DIRECTION << 7);
    iv[15] = iv[7];

    //L,the length of key stream,taking 32bit as a unit
    L = (LENGTH + 31) / 32 + 2;
    k=malloc(sizeof(unsigned int)*L);
    //generate key stream k
    ZUC_GenKeyStream(IK, iv, k, L);
    //T=T^ki
    for (i = 0; i < LENGTH; i++)
    {
        if(BitValue(M, i))
        {
            ki = GetWord(k, i);
            T = T ^ ki; }
    }
    //T=T^kLENGTH
    ki = GetWord(k, LENGTH);
    T = T ^ ki;

    //MAC=T^k(32*(L-1))
    ki = GetWord(k, 32 * (L - 1));
    MAC = T ^ ki;
    free(k);
    return MAC;
}

//生成密钥流测试
void ZUC_GenKey_Test()
{
    unsigned char k[16]={0x3d,0x4c,0x4b,0xe9,0x6a,0x82,0xfd,0xae,0xb5,0x8f,0x64,0x1d,0xb1,0x7b,0x45,0x5b};
    unsigned char iv[16]={0x84,0x31,0x9a,0xa8,0xde,0x69,0x15,0xca,0x1f,0x6b,0xda,0x6b,0xfb,0xd8,0xc7,0x66}; unsigned int Std_Keystream[2]={0x14f1c272,0x3279c419};
    int KeystreamLen=2;//the length of key stream
    unsigned int Keystream[2];

    printf("k=%08x\n",k);
    printf("iv=%08x\n",iv);
    printf("KeystreamLen=%d\n",KeystreamLen);

    printf("\n开始生成秘钥流：\n------------------------------------------------------------");
    ZUC_GenKeyStream(k, iv,Keystream, KeystreamLen);
}

//加解密测试
void ZUC_Enc_DEC_Test()
{
    int i;
    unsigned char key[16] =
            {0x17,0x3d,0x14,0xba,0x50,0x03,0x73,0x1d,0x7a,0x60,0x04,0x94,0x70,0xf0,0x0a,0x29};
    unsigned int COUNT=0x66035492;
    unsigned char BEARER=0x0f;
    unsigned char DIRECTION=0x00;
    unsigned int plain[7] =
            {0x6cf65340,0x735552ab,0x0c9752fa,0x6f9025fe,0x0bd675d9,0x005875b2,0x00000000};
    unsigned int Std_cipher[7] =
            {0xa6c85fc6,0x6afb8533,0xaafc2518,0xdfe78494,0x0ee1e4b0,0x30238cc8,0x00000000};
    int plainlen = 0xc1;
    unsigned int cipher[7];
    unsigned int plain2[7];
    printf("明文：");
    for(i = 0; i < (plainlen + 31) / 32; i++)
    {
        printf("%08x  ", plain[i]);
    }
    printf("\n");

    ZUC_Confidentiality(key,COUNT,BEARER,DIRECTION,plain,plainlen,cipher);
    printf("\n密文：");
    for(i = 0; i < (plainlen + 31) / 32; i++)
    {
        printf("%08x  ", cipher[i]);
    }
    printf("\n");

    ZUC_Confidentiality(key,COUNT,BEARER,DIRECTION,plain,plainlen,cipher);
    printf("\n密文：");
    for(i = 0; i < (plainlen + 31) / 32; i++)
    {
        printf("%08x  ", cipher[i]);
    }
    printf("\n");
}

//完整性测试
void ZUC_Integrity_Test()
{
    unsigned int MAC;
    unsigned char  IK[16] =
            {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}; unsigned int counter=0x00000000;
    unsigned char bear=0x00;
    unsigned char direc=0x00;
    unsigned int message[1] = {0x00000000};
    int length = 1;
    unsigned int Std_MAC=0xc8a9595e;
    printf("明文消息 = %08x ",message);
    printf("\n\n****************Integrity validation****************");
    MAC=ZUC_Integrity(IK,counter,bear,direc,message,length);
    printf("\nMAC = %08x ",MAC);
}

int main()
{
    //ZUC_GenKey_Test();
    ZUC_Enc_DEC_Test();
    //ZUC_Integrity_Test();
    return  0;
}