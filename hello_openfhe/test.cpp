#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <algorithm> // Include for std::remove
#include "openfhe.h"

using namespace lbcrypto;

// Helper function to convert a hexadecimal string to a vector of integers
std::vector<int64_t> hexStringToVector(const std::string& hexString) {
    std::vector<int64_t> vec;
    for (std::size_t i = 0; i < hexString.length(); i += 2) {
        std::string byteString = hexString.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
        vec.push_back(static_cast<int64_t>(byte));
    }
    return vec;
}

// Helper function to convert a vector of integers back to a hexadecimal string
std::string vectorToHexString(const std::vector<int64_t>& vec) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int64_t byte : vec) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

// Function to encrypt a given Poseidon hash and return the secret key and encrypted data
std::tuple<std::string, std::string> encryptPoseidonHash(const std::string& poseidonHash) {
    // Initialize the context for BFV scheme
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);  // Adjust the plaintext modulus
    parameters.SetMultiplicativeDepth(1);
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKESchemeFeature::PKE);
    cc->Enable(PKESchemeFeature::LEVELEDSHE);

    // Generate keys
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    // Convert the hexadecimal string to a vector of integers
    std::vector<int64_t> hashVec = hexStringToVector(poseidonHash.substr(2)); // Remove the "0x" prefix

    // Encrypt the hash
    Plaintext plaintext = cc->MakePackedPlaintext(hashVec);
    auto ciphertext = cc->Encrypt(keys.publicKey, plaintext);

    // Convert encrypted data to hexadecimal string
    std::stringstream encryptedDataSS;
    encryptedDataSS << std::hex << std::setfill('0');
    for (const auto& poly : ciphertext->GetElements()) {
        for (size_t i = 0; i < poly.GetNumOfElements(); ++i) {
            auto val = poly.GetElementAtIndex(i);
            for (size_t j = 0; j < val.GetLength(); ++j) {
                encryptedDataSS << std::setw(2) << val[j].ConvertToInt();
            }
        }
    }
    std::string encryptedDataString = encryptedDataSS.str();

    // Output the secret key
    std::stringstream ss;
    ss << keys.secretKey;

    return {ss.str(), encryptedDataString};
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <poseidon_hash>" << std::endl;
        return 1;
    }

    std::string poseidonHash = argv[1];
    auto [secretKey, encryptedDataString] = encryptPoseidonHash(poseidonHash);

    std::cout << "Secret Key: " << secretKey << std::endl;
    std::cout << "Encrypted Data: " << encryptedDataString << std::endl;

    return 0;
}










// #include <iostream>
// #include <string>
// #include <vector>
// #include <cstdint>
// #include <iomanip>
// #include <sstream>
// #include <algorithm>
// #include "openfhe.h"

// using namespace lbcrypto;

// // Function to decrypt a given ciphertext and return the decrypted value
// int64_t decryptValue(const Ciphertext<DCRTPoly>& ciphertext, CryptoContext<DCRTPoly> cc, const PrivateKey<DCRTPoly>& secretKey) {
//     Plaintext plaintext;
//     cc->Decrypt(secretKey, ciphertext, &plaintext);
//     return plaintext->GetPackedValue()[0];
// }

// // Function to encrypt a given value and return the ciphertext
// Ciphertext<DCRTPoly> encryptValue(int64_t value, CryptoContext<DCRTPoly> cc, const KeyPair<DCRTPoly>& keys) {
//     Plaintext plaintext = cc->MakePackedPlaintext({value});
//     return cc->Encrypt(keys.publicKey, plaintext);
// }

// int main(int argc, char* argv[]) {
//     if (argc != 3) {
//         std::cerr << "Usage: " << argv[0] << " <secret_key> <encrypted_data>" << std::endl;
//         return 1;
//     }

//     std::string secretKeyStr = argv[1];
//     std::string encryptedDataString = argv[2];

//     // Initialize the context for BFV scheme
//     CCParams<CryptoContextBFVRNS> parameters;
//     parameters.SetPlaintextModulus(65537);  // Adjust the plaintext modulus
//     parameters.SetMultiplicativeDepth(1);
//     auto cc = GenCryptoContext(parameters);
//     cc->Enable(PKESchemeFeature::PKE);
//     cc->Enable(PKESchemeFeature::LEVELEDSHE);

//     // Deserialize the secret key from the string
//     std::stringstream ssKey(secretKeyStr);
//     PrivateKey<DCRTPoly> secretKey;
//     Serial::Deserialize(secretKey, ssKey, SerType::BINARY);

//     // Deserialize the ciphertext from the string
//     std::stringstream ss(encryptedDataString);
//     Ciphertext<DCRTPoly> encryptedAmount;
//     Serial::Deserialize(encryptedAmount, ss, SerType::BINARY);

//     // Decrypt the original amount (for verification purposes, can be skipped in production)
//     int64_t originalAmount = decryptValue(encryptedAmount, cc, secretKey);
//     std::cout << "Original Amount: " << originalAmount << std::endl;

//     // Create a plaintext for the amount to add
//     Plaintext plainAmountToAdd = cc->MakePackedPlaintext({1000});

//     // Homomorphically add 1000 to the encrypted amount
//     Ciphertext<DCRTPoly> updatedEncryptedAmount = cc->EvalAdd(encryptedAmount, plainAmountToAdd);

//     // Decrypt the updated amount (for verification purposes, can be skipped in production)
//     int64_t updatedAmount = decryptValue(updatedEncryptedAmount, cc, secretKey);
//     std::cout << "Updated Amount: " << updatedAmount << std::endl;

//     // Serialize the updated ciphertext
//     std::stringstream updatedEncryptedDataSS;
//     Serial::Serialize(updatedEncryptedAmount, updatedEncryptedDataSS, SerType::BINARY);

//     std::cout << "Updated Encrypted Data: " << updatedEncryptedDataSS.str() << std::endl;

//     return 0;
// }
