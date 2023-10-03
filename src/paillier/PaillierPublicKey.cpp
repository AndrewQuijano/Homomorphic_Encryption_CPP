#include <iostream>
#include <fstream>
#include <NTL/ZZ.h>
#include <string>

using namespace std;
using namespace NTL;

class PaillierPublicKey {
private:
    long key_size;
    ZZ n;
    ZZ modulus;
    ZZ g;

public:
    PaillierPublicKey(long key_size, const ZZ &n, const ZZ &modulus, const ZZ &g)
        : key_size(key_size), n(n), modulus(modulus), g(g) {}

    string toString() {
        string answer = "";
        answer += "k1 = " + to_string(key_size) + ", " + '\n';
        answer += "n = " + to_string(n) + ", " + '\n';
        answer += "modulus = " + to_string(modulus) + '\n';
        answer += "g = " + to_string(g) + '\n';
        return answer;
    }

    void writeKey(const string &paillier_public_key_file) {
        ofstream pk_file(paillier_public_key_file, ios::binary);
        if (!pk_file) {
            cerr << "Error opening public key file." << endl;
            return;
        }
        pk_file.write(reinterpret_cast<const char*>(&key_size), sizeof(key_size));
        pk_file.write(reinterpret_cast<const char*>(&n), sizeof(n));
        pk_file.write(reinterpret_cast<const char*>(&modulus), sizeof(modulus));
        pk_file.write(reinterpret_cast<const char*>(&g), sizeof(g));
        pk_file.close();
    }

    static PaillierPublicKey readKey(const string &paillier_public_key) {
        long key_size;
        ZZ n, modulus, g;

        ifstream pk_file(paillier_public_key, ios::binary);
        if (!pk_file) {
            cerr << "Error opening public key file." << endl;
            return PaillierPublicKey(0, ZZ(0), ZZ(0), ZZ(0));
        }
        pk_file.read(reinterpret_cast<char*>(&key_size), sizeof(key_size));
        pk_file.read(reinterpret_cast<char*>(&n), sizeof(n));
        pk_file.read(reinterpret_cast<char*>(&modulus), sizeof(modulus));
        pk_file.read(reinterpret_cast<char*>(&g), sizeof(g));
        pk_file.close();

        return PaillierPublicKey(key_size, n, modulus, g);
    }

    ZZ getN() {
        return n;
    }

    ZZ getModulus() {
        return modulus;
    }

    bool equals(const PaillierPublicKey &other) {
        return this->toString() == other.toString();
    }
};

int main() {
    string paillier_public_key_file = "paillier.pub";
    PaillierPublicKey pk = PaillierPublicKey(2048, ZZ(123456789), ZZ(987654321), ZZ(987));
    
    pk.writeKey(paillier_public_key_file);

    PaillierPublicKey read_pk = PaillierPublicKey::readKey(paillier_public_key_file);

    if (pk.equals(read_pk)) {
        cout << "Keys are equal." << endl;
    } else {
        cout << "Keys are not equal." << endl;
    }

    return 0;
}
