#include "paillier.h"

ZZ generateCoprimeNumber(const ZZ& n) {
    ZZ ret;
    while (true) {
        ret = RandomBnd(n);
        if (NTL::GCD(ret, n) == 1) { return ret; }
    }
}

Paillier::Paillier() {
    /* Length in bits. */
    long keyLength = 512;
    ZZ p, q;
    GenPrimePair(p, q, keyLength);
    modulus = p * q;
    generator = modulus + 1;
    ZZ phi = (p - 1) * (q - 1);
    // LCM(p, q) = p * q / GCD(p, q);
    lambda = phi / NTL::GCD(p - 1, q - 1);
    lambdaInverse = NTL::InvMod(lambda, modulus);//u=L(g^lambda mod n^2)^{-1}
}

Paillier::Paillier(const ZZ& modulus, const ZZ& lambda) {
    this->modulus = modulus;
    generator = this->modulus + 1;
    this->lambda = lambda;
    lambdaInverse = NTL::InvMod(this->lambda, this->modulus);
}

void Paillier::GenPrimePair(ZZ& p, ZZ& q,
                               long keyLength) {
    while (true) {
        long err = 80;
        p = NTL::GenPrime_ZZ(keyLength/2, err); 
        ZZ q = NTL::GenPrime_ZZ(keyLength/2, err);
        while (p != q) {
            q = NTL::GenPrime_ZZ(keyLength/2, err);
        }
        ZZ n = p * q;
        ZZ phi = (p - 1) * (q - 1);
        if (NTL::GCD(n, phi) == 1) return;
    }
}

ZZ Paillier::encrypt(const ZZ& message) {
    ZZ random = generateCoprimeNumber(modulus);
    ZZ ciphertext = 
        NTL::PowerMod(generator, message, modulus * modulus) *
        NTL::PowerMod(random, modulus, modulus * modulus);
    return ciphertext % (modulus * modulus);
}

ZZ Paillier::encrypt(const ZZ& message, const ZZ& random) {
    //c=(g^m*r^n) mod n^2
    ZZ ciphertext = 
        NTL::PowerMod(generator, message, modulus * modulus) *
        NTL::PowerMod(random, modulus, modulus * modulus);
    return ciphertext % (modulus * modulus);
}

ZZ Paillier::decrypt(const ZZ& ciphertext) {
    /* NOTE: NTL::PowerMod will fail if the first input is too large
     * (which I assume means larger than modulus).
     * m=L(c^lambda mod n^2)*u
     */
    ZZ deMasked = NTL::PowerMod(
            ciphertext, lambda, modulus * modulus);
    ZZ power = L_function(deMasked);
    return (power * lambdaInverse) % modulus;//u=lambdaInverse
}


ZZ Paillier::hom_add(const ZZ& ciphertext1,const ZZ& ciphertext2){
    return (ciphertext1*ciphertext2)% (modulus * modulus);
}


ZZ Paillier::hom_add_const(const ZZ& ciphertext,const ZZ p){
    return (ciphertext*(PowerMod(generator,p,modulus * modulus)))% (modulus * modulus);
}
ZZ Paillier::hom_mult(const ZZ& ciphertext,const ZZ p){
    return PowerMod(ciphertext, p, modulus * modulus);
}