// C����ʵ��
#include<stdio.h>
#include<string.h>
/*
	�ο����ӣ�https://blog.csdn.net/zidane_2014/article/details/37988657
*/
int IP_Table[64] = {                                     //IP�û�����
	58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };
int E_Table[48] = {                                    //��չ����
	32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
	8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1 };
int P_Table[32] = {                                             //  P ��
	16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
	2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25 };
int IPR_Table[64] = {                                    //��IP�û�����
	40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25 };
int PC1_Table[56] = {                               //��Կ��һ���û�����
	57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4 };
int PC2_Table[48] = {                          // ��Կ�ڶ����û�����
	14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
int S_Box[8][4][16] = {                     //8��S��   ��ά����
	// S1 
	14, 4,  13,	 1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
	0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
	4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
	15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
	// S2 
	15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
	3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
	0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
	13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
	// S3 
	10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
	13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
	13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
	1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
	// S4 
	7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
	13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
	10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
	3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
	// S5 
	2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
	14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
	4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
	11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,
	// S6 
	12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
	10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
	9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
	4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,
	// S7 
	4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
	13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
	1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
	6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
	// S8 
	13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
	1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
	7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
	2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
};
static void CharToBit(const char input[], int output[])//��CHARת��ΪINT
{
	int i, j;
	for (j = 0; j < 8; j++)
	{
		for (i = 0; i < 8; i++)
		{
			output[7 * (j + 1) - i + j] = (input[j] >> i) & 1;
		}
	}
};
static void BitToChar(const int intput[], char output[])//��INTת��ΪCHAR
{
	int i, j;
	for (j = 0; j < 8; j++)
	{
		for (i = 0; i < 8; i++)
		{
			output[j] = output[j] * 2 + intput[i + 8 * j];
		}
	}
};
static void Xor(int* INA, int* INB, int len)//������
{
	int i;
	for (i = 0; i < len; i++)
	{
		*(INA + i) = *(INA + i) ^ *(INB + i);
	}
};
static  void IP(const int input[64], int output[64], int table[64])//��ʼIP�û�
{
	int i;
	for (i = 0; i < 64; i++)
	{
		output[i] = input[table[i] - 1];//��1���������٣���
	}
};
static  void E(const int input[32], int output[48], int table[48])//E��չ
{
	int i;
	for (i = 0; i < 48; i++)
	{
		output[i] = input[table[i] - 1];
	}
};
static  void P(const int input[32], int output[32], int table[32])//P�û�
{
	int i;
	for (i = 0; i < 32; i++)
	{
		output[i] = input[table[i] - 1];
	}
};
static  void IP_In(const int input[64], int output[64], int table[64])//��IP
{
	int i;
	for (i = 0; i < 64; i++)
	{
		output[i] = input[table[i] - 1];
	}
};
static  void PC_1(const int input[64], int output[56], int table[56])//PC_1
{
	int i;
	for (i = 0; i < 56; i++)
	{
		output[i] = input[table[i] - 1];
	}
};
static  void PC_2(const int input[56], int output[48], int table[48])//PC_2
{
	int i;
	for (i = 0; i < 48; i++)
	{
		output[i] = input[table[i] - 1];
	}
};
static  void S(const int input[48], int output[32], int table[8][4][16])//S��ѹ��
{
	int i = 0;
	int j = 0;
	int INT[8];
	for (; i < 48; i = i + 6)
	{
		INT[j] = table[j][(input[i] << 1) + (input[i + 5])][(input[i + 1] << 3) + (input[i + 2] << 2) + (input[i + 3] << 1) + (input[i + 4])];
		j++;
	}
	for (j = 0; j < 8; j++)
	{
		for (i = 0; i < 4; i++)
		{
			output[3 * (j + 1) - i + j] = (INT[j] >> i) & 1;
		}
	}
};
static void F_func(int input[32], int output[32], int subkey[48])//���DES�㷨�ֱ任
{
	int len = 48;
	int temp[48] = { 0 };
	int temp_1[32] = { 0 };
	E(input, temp, E_Table);//E��չ�任��32bit -> 48bit��
	Xor(temp, subkey, len);//������Կ���
	S(temp, temp_1, S_Box);//ѹ���任��S�У���48bit -> 32bit��
	P(temp_1, output, P_Table);//P�û�
};
static void RotateL(const int input[28], int output[28], int leftCount)//�������Կ��չ��ѭ������
{
	int i;
	int len = 28;
	for (i = 0; i < len; i++)
	{
		output[i] = input[(i + leftCount) % len];
	}
};
static void  subKey_fun(const int input[64], int Subkey[16][48])//���16������Կ����
{
	int loop = 1, loop_2 = 2;
	int i, j;
	int c[28], d[28];
	int pc_1[56] = { 0 };
	int pc_2[16][56] = { 0 };
	int rotatel_c[16][28] = { 0 };
	int rotatel_d[16][28] = { 0 };
	PC_1(input, pc_1, PC1_Table);
	for (i = 0; i < 28; i++)
	{
		c[i] = pc_1[i];
		d[i] = pc_1[i + 28];
	}
	int leftCount = 0;
	for (i = 1; i < 17; i++)
	{
		if (i == 1 || i == 2 || i == 9 || i == 16)
		{
			leftCount += loop;
			RotateL(c, rotatel_c[i - 1], leftCount);
			RotateL(d, rotatel_d[i - 1], leftCount);
		}
		else
		{
			leftCount += loop_2;
			RotateL(c, rotatel_c[i - 1], leftCount);
			RotateL(d, rotatel_d[i - 1], leftCount);
		}
	}
	for (i = 0; i < 16; i++)
	{
		for (j = 0; j < 28; j++)
		{
			pc_2[i][j] = rotatel_c[i][j];
			pc_2[i][j + 28] = rotatel_d[i][j];
		}
	}
	for (i = 0; i < 16; i++)
	{
		PC_2(pc_2[i], Subkey[i], PC2_Table);
	}
};
//DES��������
static void  DES_Efun(char input[8], char key_in[8], int output[64])
{
	int Ip[64] = { 0 };//�洢��ʼ�û���ľ���
	int output_1[64] = { 0 }; //���64bit������
	int subkeys[16][48]; //16������Կ��48bit��K_i��
	int chartobit[64] = { 0 };
	int key[64];
	int l[17][32], r[17][32];
	CharToBit(input, chartobit);//�������������Ϣת��Ϊ64����������
	IP(chartobit, Ip, IP_Table);//IP��ʼ�û�
	CharToBit(key_in, key);//������ĳ�ʼ��Կת��Ϊ��������
	subKey_fun(key, subkeys);//��Կ����
	//��0���е�IP�û����Ϊ����������
    for (int i = 0; i < 32; i++)
	{
		l[0][i] = Ip[i];
		r[0][i] = Ip[32 + i];
	}
	for (int j = 1; j < 16; j++)//ǰ15�ֵĲ���
	{
		for (int k = 0; k < 32; k++)//ÿ�ֽ��Ұ벿��ֱ�Ӹ�ֵ����һ����벿��
		{
			l[j][k] = r[j - 1][k];
		}
		F_func(r[j - 1], r[j], subkeys[j - 1]);//ʹ�ó�ʼ��Կ������
		Xor(r[j], l[j - 1], 32);//��f��������벿�����õ���һ���Ұ벿��
	}
	int t = 0;
	for (t = 0; t < 32; t++)//���һ�ֵĲ���
	{
		r[16][t] = r[15][t]; //����15�ֵ��Ұ벿��ֱ�Ӹ�ֵ����16�ֵ��Ұ벿��
	}
	F_func(r[15], l[16], subkeys[15]);//ʹ�õ�16������Կ
	Xor(l[16], l[15], 32);//��f��������벿�����õ���һ����벿��
	for (t = 0; t < 32; t++)//�ϲ����Ұ벿��
	{
		output_1[t] = l[16][t];
		output_1[32 + t] = r[16][t];
	}
    //IP���û�
	IP_In(output_1, output, IPR_Table);
};
//���DES��������
static void  DES_Dfun(int input[64], char key_in[8], char output[8])
{
	int Ip[64] = { 0 };//�洢��ʼ�û���ľ���
	int output_1[64] = { 0 };
	int output_2[64] = { 0 };
	int subkeys[16][48];
	int chartobit[64] = { 0 };
	int key[64];
	int l[17][32], r[17][32];
	IP(input, Ip, IP_Table);//��ȷ��IP��ʼ�û���
	CharToBit(key_in, key);//��ȷ��
	subKey_fun(key, subkeys);//��ȷ��
	for (int i = 0; i < 32; i++)
	{
		l[0][i] = Ip[i];
		r[0][i] = Ip[32 + i];
	}
	for (int j = 1; j < 16; j++)//ǰ15�ֵĲ���
	{
		for (int k = 0; k < 32; k++)
		{
			l[j][k] = r[j - 1][k];
		}
		F_func(r[j - 1], r[j], subkeys[16 - j]);//ʹ�ó�ʼ��Կ������
		Xor(r[j], l[j - 1], 32);
	}
	int t = 0;
	for (t = 0; t < 32; t++)//���һ�ֵĲ���
	{
		r[16][t] = r[15][t];
	}
	F_func(r[15], l[16], subkeys[0]);
	Xor(l[16], l[15], 32);
	for (t = 0; t < 32; t++)
	{
		output_1[t] = l[16][t];
		output_1[32 + t] = r[16][t];
	}
	IP_In(output_1, output_2, IPR_Table);
	BitToChar(output_2, output);
};

int main()
{
	int output[64] = { 0 };
	char MIN[9] = { 0 }; // ����
	char MI[9] = { 0 };  //��Կ
	printf("���������ģ�8���ַ�����");
	gets(MIN);
	printf("��������Կ��8���ַ�����");
	gets(MI);
	DES_Efun(MIN, MI, output);
	printf("��������:\n");
	for (int i = 0; i < 64; i++)
	{
		printf("%d", output[i]);
		if ((i + 1) % 4 == 0)
			printf("\n");
	}
	printf("\n");
	printf("���ܹ���\n");
	DES_Dfun(output, MI, MIN);
	printf("��������:\n");
	for (int i = 0; i < 8; i++)
	{
		printf("%c", MIN[i]);
	}
	printf("\n");
	return 0;
}