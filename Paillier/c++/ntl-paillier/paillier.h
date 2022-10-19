#include <NTL/ZZ.h>
#include <NTL/ZZ_pXFactoring.h>

using namespace NTL;

class Paillier {
    public:
    /* Completely generate everything, from scratch */
    Paillier();
    Paillier(const ZZ& modulus, const ZZ& lambda); 
    //Paillier(path to public key, path to private key).

    /* Paillier encryption function. Takes in a message from the
     * integers modulo n (Paillier.modulus) and returns a message in
     * the integers modulo n**2.
     *
     * Parameters
     * ==========
     * ZZ message : The message to encrypt, as a number.
     *
     * Returns
     * =======
     * NTL:ZZ ciphertext : The encyrpted message.
     */
    ZZ encrypt(const ZZ& message); 

    /* Paillier encryption function with provided randomness, if user
     * wants to provide their own randomness.
     *
     * Random number should be coprime to modulus.
     *
     * Parameters
     * ==========
     * ZZ message : The message to encrypt, as a number.
     * ZZ random : The random mask.
     *
     * Returns
     * =======
     * NTL:ZZ ciphertext : The encyrpted message.
     */
    ZZ encrypt(const ZZ& message, const ZZ& random); 

    /* Paillier decryption function. Takes in a cipertext from Z mod
     * n**2 and returns a message in the Z mod n.
     *
     * Parameters
     * ==========
     * ZZ cipertext : The encrypted message.
     *
     * Returns
     * =======
     * ZZ message : The original message.
     */
    ZZ decrypt(const ZZ& ciphertext);

    /*
     * c_1*c_2=Enc(m_1+m_2,r_1*r_2)
     */
    ZZ hom_add(const ZZ& ciphertext1,const ZZ& ciphertext2);

    /*
     * c_1*g^p=Enc(m_1+p,r_1)
     */
    ZZ hom_add_const(const ZZ& ciphertext,const ZZ p);

    /*
     * c_1^m=Enc(m*c_1,r_1^m)
     */
    ZZ hom_mult(const ZZ& ciphertext,const ZZ p);

    private:
    /* modulus = pq, where p and q are primes */
    ZZ modulus;
    ZZ generator;
    ZZ lambda;
    ZZ lambdaInverse;

    /* The L function in the paillier cryptosystem.  See
     * <https://en.wikipedia.org/wiki/Paillier_cryptosystem> for more
     * details.
     *
     * Parameters
     * ==========
     * ZZ x : The argument to L.
     * ZZ n : The paillier modulus.
     *
     * Returns
     * =======
     * ZZ result : (x - 1) / n
     */
    ZZ L_function(const ZZ& n) { return (n - 1) / modulus; }

    void GenPrimePair(ZZ& p, ZZ& q, long keyLength); 
};
