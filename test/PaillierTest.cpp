#include <iostream>
#include <vector>
#include <NTL/ZZ.h> // Include the NTL library
using namespace NTL;

// PaillierPublicKey and PaillierPrivateKey class definitions here...

class PaillierTest {
public:
    // Constants here...

    void generate_keys() {
        PaillierKeyPairGenerator pa;
        pa.initialize(KEY_SIZE, nullptr);
        KeyPair paillier = pa.generateKeyPair();
        public_key = dynamic_cast<PaillierPublicKey*>(paillier.getPublic());
        private_key = dynamic_cast<PaillierPrivateKey*>(paillier.getPrivate());
    }

    void test_decrypt() {
        a = PaillierCipher::decrypt(PaillierCipher::encrypt(ZZ(10), public_key), private_key);
        assert(a == ZZ(10));
    }

    void test_addition() {
        a = PaillierCipher::encrypt(ZZ(10), public_key);
        a = PaillierCipher::add(a, a, public_key);
        assert(a == ZZ(20));

        a = PaillierCipher::encrypt(ZZ(10), public_key);
        a = PaillierCipher::add_plaintext(a, ZZ(10), public_key);
        assert(a == ZZ(20));
    }

    void test_multiply() {
        a = PaillierCipher::multiply(PaillierCipher::encrypt(ZZ(10), public_key), ZZ(10), public_key);
        assert(a == ZZ(100));
    }

    void test_subtract() {
        a = PaillierCipher::encrypt(ZZ(20), public_key);
        a = PaillierCipher::subtract(a, PaillierCipher::encrypt(ZZ(10), public_key), public_key);
        assert(a == ZZ(10));

        a = PaillierCipher::subtract_plaintext(PaillierCipher::encrypt(ZZ(20), public_key), ZZ(10), public_key);
        assert(a == ZZ(10));
    }

    void test_divide() {
        a = PaillierCipher::divide(PaillierCipher::encrypt(ZZ(100), public_key), ZZ(2), public_key);
        assert(a == ZZ(50));
    }

    void paillier_test_sum() {
        std::vector<ZZ> values(10);
        std::vector<ZZ> list_values;

        for (int i = 0; i < values.size(); i++) {
            values[i] = PaillierCipher::encrypt(ZZ(10), public_key);
            list_values.push_back(PaillierCipher::encrypt(ZZ(10), public_key));
        }

        a = PaillierCipher::sum(values, public_key, 11);
        assert(a == ZZ(100));

        a = PaillierCipher::sum(list_values, public_key, 5);
        assert(a == ZZ(50));
    }

    void paillier_test_product_sum() {
        std::vector<ZZ> encrypted_values(10);
        std::vector<long> plain_values(10);
        std::vector<ZZ> encrypted_list_values;
        std::vector<long> plain_list_values;

        for (int i = 0; i < encrypted_values.size(); i++) {
            encrypted_values[i] = PaillierCipher::encrypt(ZZ(10), public_key);
            plain_values[i] = 2;

            encrypted_list_values.push_back(PaillierCipher::encrypt(ZZ(10), public_key));
            plain_list_values.push_back(2);
        }

        a = PaillierCipher::sum_product(encrypted_values, plain_values, public_key);
        assert(a == ZZ(200));

        a = PaillierCipher::sum_product(encrypted_list_values, plain_list_values, public_key);
        assert(a == ZZ(200));
    }

    void paillier_signature() {
        ZZ FORTY_TWO(42);

        std::vector<ZZ> signed_answer = PaillierSignature::sign(FORTY_TWO, private_key);

        for (int i = 0; i < 1000; i++) {
            bool answer = PaillierSignature::verify(ZZ(i), signed_answer, public_key);
            if (i == 42) {
                assert(answer);
            }
            else {
                assert(!answer);
            }
        }
    }

private:
    PaillierPublicKey* public_key;
    PaillierPrivateKey* private_key;
    ZZ a;
};

int main() {
    PaillierTest test;
    test.generate_keys();
    test.test_decrypt();
    test.test_addition();
    test.test_multiply();
    test.test_subtract();
    test.test_divide();
    test.paillier_test_sum();
    test.paillier_test_product_sum();
    test.paillier_signature();
    return 0;
}