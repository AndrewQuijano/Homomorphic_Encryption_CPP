#ifndef PAILLIER_CIPHER_H
#define PAILLIER_CIPHER_H

#include <NTL/ZZ.h>
#include <vector>
#include "PaillierPublicKey.h"
#include "PaillierPrivateKey.h"

class PaillierCipher {
public:
    static NTL::ZZ encrypt(const NTL::ZZ &plaintext, const PaillierPublicKey &public_key);
    static NTL::ZZ encrypt(long plaintext, const PaillierPublicKey &public_key);
    static NTL::ZZ decrypt(const NTL::ZZ &ciphertext, const PaillierPrivateKey &private_key);
    static NTL::ZZ add(const NTL::ZZ &ciphertext1, const NTL::ZZ &ciphertext2, const PaillierPublicKey &public_key);
    static NTL::ZZ add_plaintext(const NTL::ZZ &ciphertext, const NTL::ZZ &plaintext, const PaillierPublicKey &public_key);
    static NTL::ZZ subtract(const NTL::ZZ &ciphertext1, const NTL::ZZ &ciphertext2, const PaillierPublicKey &public_key);
    static NTL::ZZ subtract_plaintext(const NTL::ZZ &ciphertext, const NTL::ZZ &plaintext, const PaillierPublicKey &public_key);
    static NTL::ZZ multiply(const NTL::ZZ &ciphertext, const NTL::ZZ &plaintext, const PaillierPublicKey &public_key);
    static NTL::ZZ multiply(const NTL::ZZ &ciphertext1, long scalar, const PaillierPublicKey &public_key);
    static NTL::ZZ divide(const NTL::ZZ &ciphertext, const NTL::ZZ &divisor, const PaillierPublicKey &public_key);
    static NTL::ZZ sum(const std::vector<NTL::ZZ> &values, const PaillierPublicKey &public_key);
    static NTL::ZZ sum(const std::vector<NTL::ZZ> &values, const PaillierPublicKey &public_key, int limit);
    static NTL::ZZ sum(const std::vector<NTL::ZZ> &values, const PaillierPublicKey &public_key);
    static NTL::ZZ sum(const std::vector<NTL::ZZ> &values, const PaillierPublicKey &public_key, int limit);
    static NTL::ZZ sum_product(const std::vector<NTL::ZZ> &ciphertext, const std::vector<long> &plaintext, const PaillierPublicKey &public_key);
    static NTL::ZZ sum_product(const std::vector<NTL::ZZ> &ciphertext, const std::vector<long> &plaintext, const PaillierPublicKey &public_key);
    static NTL::ZZ sum_product(const std::vector<NTL::ZZ> &ciphertext, const std::vector<long> &plaintext, const PaillierPublicKey &public_key);
};

#endif // PAILLIER_CIPHER_H
