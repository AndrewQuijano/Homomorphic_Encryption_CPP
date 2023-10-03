#ifndef PAILLIER_KEY_PAIR_GENERATOR_H
#define PAILLIER_KEY_PAIR_GENERATOR_H

#include <NTL/ZZ.h>
#include "PaillierPublicKey.h"
#include "PaillierPrivateKey.h"
#include <vector>

class PaillierKeyPairGenerator {
public:
    PaillierKeyPairGenerator();
    void initialize(int key_size);
    std::pair<PaillierPublicKey, PaillierPrivateKey> generateKeyPair();
    PaillierPrivateKey generatePrivateKey();
    PaillierPublicKey generatePublicKey();
    NTL::ZZ find_g(NTL::ZZ g, const NTL::ZZ &lambda, const NTL::ZZ &modulus, const NTL::ZZ &n);
    NTL::ZZ find_alpha(const NTL::ZZ &LCM);

private:
    int key_size;
};

#endif // PAILLIER_KEY_PAIR_GENERATOR_H
