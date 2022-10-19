//参考：https://blog.csdn.net/SOFAStack/article/details/123366669   https://tongsuo.readthedocs.io/zh/latest/Tutorial/PHE/ec-elgamal-sample/

#include <stdio.h>
#include <time.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#define CLOCKS_PER_MSEC (CLOCKS_PER_SEC/1000)

int main(int argc, char *argv[])
{
    int ret = -1;
    uint32_t r;
    //密钥生成
    clock_t begin, end;
    EC_KEY *sk_eckey = NULL, *pk_eckey = NULL;
    EC_ELGAMAL_CTX *ctx1 = NULL, *ctx2 = NULL;
    EC_ELGAMAL_CIPHERTEXT *c1 = NULL, *c2 = NULL, *c3 = NULL;
    EC_ELGAMAL_DECRYPT_TABLE *table = NULL;
    FILE *pk_file = fopen("ec-pk.pem", "rb");
    FILE *sk_file = fopen("ec-sk.pem", "rb");
    if ((pk_eckey = PEM_read_EC_PUBKEY(pk_file, NULL, NULL, NULL)) == NULL)
        goto err;
    if ((sk_eckey = PEM_read_ECPrivateKey(sk_file, NULL, NULL, NULL)) == NULL)
        goto err;

    if ((ctx1 = EC_ELGAMAL_CTX_new(pk_eckey)) == NULL)
        goto err;
    if ((ctx2 = EC_ELGAMAL_CTX_new(sk_eckey)) == NULL)
        goto err;

    //创建解密表
    begin = clock();
    if ((table = EC_ELGAMAL_DECRYPT_TABLE_new(ctx2, 0)) == NULL)
        goto err;

    EC_ELGAMAL_CTX_set_decrypt_table(ctx2, table);
    end = clock();
    printf("EC_ELGAMAL_DECRYPT_TABLE_new(1) cost: %lfms\n", (double)(end - begin)/CLOCKS_PER_MSEC);

    if ((c1 = EC_ELGAMAL_CIPHERTEXT_new(ctx1)) == NULL)
        goto err;
    if ((c2 = EC_ELGAMAL_CIPHERTEXT_new(ctx1)) == NULL)
        goto err;

    //加密20000021
    begin = clock();
    if (!EC_ELGAMAL_encrypt(ctx1, c1, 20000021))
        goto err;
    end = clock();
    printf("EC_ELGAMAL_encrypt(20000021) cost: %lfms\n", (double)(end - begin)/CLOCKS_PER_MSEC);

    //加密500
    begin = clock();
    if (!EC_ELGAMAL_encrypt(ctx1, c2, 500))
        goto err;
    end = clock();
    printf("EC_ELGAMAL_encrypt(500) cost: %lfms\n", (double)(end - begin)/CLOCKS_PER_MSEC);

    if ((c3 = EC_ELGAMAL_CIPHERTEXT_new(ctx1)) == NULL)
        goto err;

    //密文相加：20000021+500
    begin = clock();
    if (!EC_ELGAMAL_add(ctx1, c3, c1, c2))
        goto err;
    end = clock();
    printf("EC_ELGAMAL_add(c: 2000021,c: 500) cost: %lfms\n", (double)(end - begin)/CLOCKS_PER_MSEC);

    //解密：20000021+500
    begin = clock();
    if (!(EC_ELGAMAL_decrypt(ctx2, &r, c3)))
        goto err;
    end = clock();
    printf("EC_ELGAMAL_decrypt(c: 20000021,c: 500) result: %d, cost: %lfms\n", r, (double)(end - begin)/CLOCKS_PER_MSEC);

    //标量乘：500*800
    begin = clock();
    if (!EC_ELGAMAL_mul(ctx1, c3, c2, 800))
        goto err;
    end = clock();
    printf("EC_ELGAMAL_mul(c: 500,m: 800) cost: %lfms\n", (double)(end - begin)/CLOCKS_PER_MSEC);

    //解密：500*800
    begin = clock();
    if (!(EC_ELGAMAL_decrypt(ctx2, &r, c3)))
        goto err;
    end = clock();
    printf("EC_ELGAMAL_decrypt(c: 500,m: 800) result: %d, cost: %lfms\n", r, (double)(end - begin)/CLOCKS_PER_MSEC);

    //将密文500*800编码为二进制文件
    printf("EC_ELGAMAL_CIPHERTEXT_encode size: %zu\n", EC_ELGAMAL_CIPHERTEXT_encode(ctx2, NULL, 0, NULL, 1));

    ret = 0;
    err:
    EC_KEY_free(sk_eckey);
    EC_KEY_free(pk_eckey);
    EC_ELGAMAL_DECRYPT_TABLE_free(table);
    EC_ELGAMAL_CIPHERTEXT_free(c1);
    EC_ELGAMAL_CIPHERTEXT_free(c2);
    EC_ELGAMAL_CIPHERTEXT_free(c3);
    EC_ELGAMAL_CTX_free(ctx1);
    EC_ELGAMAL_CTX_free(ctx2);
    fclose(sk_file);
    fclose(pk_file);
    return ret;
}