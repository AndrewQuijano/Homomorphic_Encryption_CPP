#include <NTL/ZZ.h>
#include <vector>

using namespace NTL;
using namespace std;

class PaillierPublicKey {
public:
    ZZ n, g, modulus;
};

class PaillierPrivateKey {
public:
    ZZ lambda, modulus, rho;
};

class HomomorphicException {
public:
    string message;
    HomomorphicException(const string &msg) : message(msg) {}
};

ZZ NEG_ONE = -1;

ZZ encrypt(ZZ plaintext, const PaillierPublicKey &public_key) {
    if (plaintext < 0) {
        throw HomomorphicException("Encryption Invalid Parameter: the plaintext is not in Zu (plaintext < 0)");
    }
    else if (plaintext >= public_key.n) {
        throw HomomorphicException("Encryption Invalid Parameter: the plaintext is not in N (plaintext >= N)");
    }

    ZZ randomness = RandomBnd(public_key.n);
    ZZ tmp1, tmp2;
    PowerMod(tmp1, public_key.g, plaintext, public_key.modulus);
    PowerMod(tmp2, randomness, public_key.n, public_key.modulus);
    ZZ ciphertext = MulMod(tmp1, tmp2, public_key.modulus);
    return ciphertext;
}

ZZ encrypt(long plaintext, const PaillierPublicKey &public_key) {
    return encrypt(to_ZZ(plaintext), public_key);
}

ZZ decrypt(const ZZ &ciphertext, const PaillierPrivateKey &private_key) {
    if (ciphertext < 0) {
        throw HomomorphicException("decryption Invalid Parameter : the cipher text is not in Zn");
    }
    else if (ciphertext > private_key.modulus) {
        throw HomomorphicException("decryption Invalid Parameter : the cipher text is not in Zn");
    }

    ZZ tmp;
    PowerMod(tmp, ciphertext, private_key.lambda, private_key.modulus);
    ZZ plaintext = MulMod(tmp, private_key.rho, private_key.n);
    return plaintext;
}

ZZ add(const ZZ &ciphertext1, const ZZ &ciphertext2, const PaillierPublicKey &public_key) {
    if (ciphertext1 < 0 || ciphertext1 >= public_key.modulus) {
        throw HomomorphicException("PaillierAdd Invalid Parameter ciphertext1");
    }
    else if (ciphertext2 < 0 || ciphertext2 >= public_key.modulus) {
        throw HomomorphicException("PaillierAdd Invalid Parameter ciphertext2");
    }

    ZZ result = MulMod(ciphertext1, ciphertext2, public_key.modulus);
    return result;
}

ZZ add_plaintext(const ZZ &ciphertext, const ZZ &plaintext, const PaillierPublicKey &public_key) {
    if (ciphertext < 0 || ciphertext >= public_key.modulus) {
        throw HomomorphicException("Paillier add_plaintext Invalid Parameter ciphertext");
    }
    else if (plaintext < NEG_ONE || plaintext >= public_key.n) {
        throw HomomorphicException("Paillier add_plaintext Invalid Parameter plaintext");
    }

    ZZ tmp;
    PowerMod(tmp, public_key.g, plaintext, public_key.modulus);
    ZZ result = MulMod(ciphertext, tmp, public_key.modulus);
    return result;
}

ZZ subtract(const ZZ &ciphertext1, const ZZ &ciphertext2, const PaillierPublicKey &public_key) {
    ZZ neg_ciphertext2;
    MulMod(neg_ciphertext2, ciphertext2, public_key.n - 1, public_key.modulus);
    ZZ result = MulMod(ciphertext1, neg_ciphertext2, public_key.modulus);
    return result;
}

ZZ subtract_plaintext(const ZZ &ciphertext, const ZZ &plaintext, const PaillierPublicKey &public_key) {
    ZZ inverse;
    MulMod(inverse, plaintext * NEG_ONE, public_key.n, public_key.n);
    return add_plaintext(ciphertext, inverse, public_key);
}

ZZ multiply(const ZZ &ciphertext, const ZZ &plaintext, const PaillierPublicKey &public_key) {
    if (ciphertext < 0 || ciphertext >= public_key.modulus) {
        throw HomomorphicException("PaillierCipher Multiply Invalid Parameter ciphertext");
    }
    if (plaintext < 0 || plaintext >= public_key.n) {
        throw HomomorphicException("PaillierCipher Invalid Parameter plaintext");
    }

    ZZ result;
    PowerMod(result, ciphertext, plaintext, public_key.modulus);
    return result;
}

ZZ divide(const ZZ &ciphertext, const ZZ &divisor, const PaillierPublicKey &public_key) {
    ZZ inv;
    InvMod(inv, divisor, public_key.n);
    return multiply(ciphertext, inv, public_key);
}

ZZ L(const ZZ &u, const ZZ &n) {
    return DivSub(u, 1, n);
}

ZZ sum(const vector<ZZ> &values, const PaillierPublicKey &public_key) {
    ZZ sum = encrypt(0, public_key);
    for (const ZZ &value : values) {
        sum = add(sum, value, public_key);
    }
    return sum;
}

ZZ sum(const vector<ZZ> &values, const PaillierPublicKey &public_key, int limit) {
    if (limit > values.size()) {
        return sum(values, public_key);
    }
    ZZ sum = encrypt(0, public_key);
    if (limit <= 0) {
        return sum;
    }
    for (int i = 0; i < limit; i++) {
        sum = add(sum, values[i], public_key);
    }
    return sum;
}

ZZ sum(const vector<long> &values, const PaillierPublicKey &public_key) {
    ZZ sum = encrypt(0, public_key);
    for (long value : values) {
        sum = add(sum, to_ZZ(value), public_key);
    }
    return sum;
}

ZZ sum(const vector<long> &values, const PaillierPublicKey &public_key, int limit) {
    if (limit > values.size()) {
        return sum(values, public_key);
    }
    ZZ sum = encrypt(0, public_key);
    if (limit <= 0) {
        return sum;
    }
    for (int i = 0; i < limit; i++) {
        sum = add(sum, to_ZZ(values[i]), public_key);
    }
    return sum;
}

ZZ sum_product(const vector<ZZ> &ciphertext, const vector<long> &plaintext, const PaillierPublicKey &public_key) {
    if (ciphertext.size() != plaintext.size()) {
        throw HomomorphicException("Lists are NOT the same size!");
    }

    ZZ sum = encrypt(0, public_key);
    for (size_t i = 0; i < ciphertext.size(); i++) {
        ZZ temp = multiply(ciphertext[i], to_ZZ(plaintext[i]), public_key);
        sum = add(temp, sum, public_key);
    }
    return sum;
}
