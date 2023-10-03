#ifndef PAILLIER_PRIVATE_KEY_H
#define PAILLIER_PRIVATE_KEY_H

#include <NTL/ZZ.h>

class PaillierPrivateKey {
public:
    NTL::ZZ lambda;
    NTL::ZZ mu;
    NTL::ZZ g;

    PaillierPrivateKey(const NTL::ZZ &lambda, const NTL::ZZ &mu, const NTL::ZZ &g);
};

#endif // PAILLIER_PRIVATE_KEY_H
