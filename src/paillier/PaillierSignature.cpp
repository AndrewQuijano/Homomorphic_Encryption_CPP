#include <iostream>
#include <vector>
#include <NTL/ZZ.h>

using namespace std;
using namespace NTL;

class PaillierPrivateKey {
public:
    ZZ lambda;
    ZZ mu;
    ZZ g;

    PaillierPrivateKey(const ZZ &lambda, const ZZ &mu, const ZZ &g) : lambda(lambda), mu(mu), g(g) {}
};

class PaillierPublicKey {
public:
    ZZ n;
    ZZ modulus;
    ZZ g;

    PaillierPublicKey(const ZZ &n, const ZZ &modulus, const ZZ &g) : n(n), modulus(modulus), g(g) {}
};

class PaillierSignature {
public:
    static vector<ZZ> sign(const ZZ &message, const PaillierPrivateKey &private_key) {
        vector<ZZ> tuple(2);
        ZZ sigma_one = PowerMod(message, private_key.lambda, private_key.g) % private_key.g;
        sigma_one = (sigma_one * private_key.mu) % private_key.n;

        ZZ sigma_two = (message * PowerMod(private_key.g, sigma_one, private_key.n) % private_key.n);
        sigma_two = PowerMod(sigma_two, InvMod(private_key.n, private_key.lambda), private_key.n);

        tuple[0] = sigma_one;
        tuple[1] = sigma_two;
        return tuple;
    }

    static bool verify(const ZZ &message, const vector<ZZ> &signed_message, const PaillierPublicKey &public_key) {
        if (signed_message.size() != 2) {
            cerr << "Invalid signature format." << endl;
            return false;
        }

        ZZ sigma_one = signed_message[0];
        ZZ sigma_two = signed_message[1];
        return verify(message, sigma_one, sigma_two, public_key);
    }

    static bool verify(const ZZ &message, const ZZ &sigma_one, const ZZ &sigma_two, const PaillierPublicKey &public_key) {
        ZZ first_part = PowerMod(public_key.g, sigma_one, public_key.modulus) % public_key.modulus;
        ZZ second_part = PowerMod(sigma_two, public_key.n, public_key.modulus) % public_key.modulus;
        ZZ product = (first_part * second_part) % public_key.modulus;
        return message == product;
    }
};

int main() {
    ZZ message, sigma_one, sigma_two;
    PaillierPrivateKey private_key(ZZ(123), ZZ(456), ZZ(789));
    PaillierPublicKey public_key(ZZ(123), ZZ(456), ZZ(789));
    
    // Sign a message
    vector<ZZ> signature = PaillierSignature::sign(message, private_key);
    
    // Verify the signature
    bool valid = PaillierSignature::verify(message, sigma_one, sigma_two, public_key);
    
    if (valid) {
        cout << "Signature is valid." << endl;
    } else {
        cout << "Signature is invalid." << endl;
    }

    return 0;
}
