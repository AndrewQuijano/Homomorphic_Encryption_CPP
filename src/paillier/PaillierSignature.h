#ifndef PAILLIER_SIGNATURE_H
#define PAILLIER_SIGNATURE_H

#include <vector>
#include <NTL/ZZ.h>
#include "PaillierPrivateKey.h"
#include "PaillierPublicKey.h"

class PaillierSignature {
public:
    static std::vector<NTL::ZZ> sign(const NTL::ZZ &message, const PaillierPrivateKey &private_key);
    static bool verify(const NTL::ZZ &message, const std::vector<NTL::ZZ> &signed_message, const PaillierPublicKey &public_key);
    static bool verify(const NTL::ZZ &message, const NTL::ZZ &sigma_one, const NTL::ZZ &sigma_two, const PaillierPublicKey &public_key);
};

#endif // PAILLIER_SIGNATURE_H
