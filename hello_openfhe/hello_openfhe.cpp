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
// #include <algorithm> // Include for std::remove
// #include "openfhe.h"

// using namespace lbcrypto;

// // Helper function to convert a hexadecimal string to a vector of integers
// std::vector<int64_t> hexStringToVector(const std::string& hexString) {
//     std::vector<int64_t> vec;
//     for (std::size_t i = 0; i < hexString.length(); i += 2) {
//         std::string byteString = hexString.substr(i, 2);
//         uint8_t byte = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
//         vec.push_back(static_cast<int64_t>(byte));
//     }
//     return vec;
// }

// // Helper function to convert a vector of integers back to a hexadecimal string
// std::string vectorToHexString(const std::vector<int64_t>& vec) {
//     std::stringstream ss;
//     ss << std::hex << std::setfill('0');
//     for (int64_t byte : vec) {
//         ss << std::setw(2) << static_cast<int>(byte);
//     }
//     return ss.str();
// }

// // Function to encrypt a given Poseidon hash and return the ciphertext, secret key, and encrypted data
// std::tuple<std::string, std::string, std::string> encryptPoseidonHash(const std::string& poseidonHash) {
//     // Initialize the context for BFV scheme
//     CCParams<CryptoContextBFVRNS> parameters;
//     parameters.SetPlaintextModulus(65537);  // Adjust the plaintext modulus
//     parameters.SetMultiplicativeDepth(1);
//     auto cc = GenCryptoContext(parameters);
//     cc->Enable(PKESchemeFeature::PKE);
//     cc->Enable(PKESchemeFeature::LEVELEDSHE);

//     // Generate keys
//     auto keys = cc->KeyGen();
//     cc->EvalMultKeyGen(keys.secretKey);

//     // Convert the hexadecimal string to a vector of integers
//     std::vector<int64_t> hashVec = hexStringToVector(poseidonHash.substr(2)); // Remove the "0x" prefix

//     // Encrypt the hash
//     Plaintext plaintext = cc->MakePackedPlaintext(hashVec);
//     auto ciphertext = cc->Encrypt(keys.publicKey, plaintext);

//     // Decrypt the ciphertext
//     Plaintext decrypted;
//     cc->Decrypt(keys.secretKey, ciphertext, &decrypted);

//     // Truncate the decrypted vector to remove padding zeros
//     std::vector<int64_t> decryptedHash = decrypted->GetPackedValue();
//     decryptedHash.erase(std::remove(decryptedHash.begin(), decryptedHash.end(), 0), decryptedHash.end());

//     // Convert decrypted data back to hexadecimal string
//     std::string decryptedHashString = "0x" + vectorToHexString(decryptedHash);

//     // Convert encrypted data to hexadecimal string
//     std::stringstream encryptedDataSS;
//     encryptedDataSS << std::hex << std::setfill('0');
//     for (const auto& poly : ciphertext->GetElements()) {
//         for (size_t i = 0; i < poly.GetNumOfElements(); ++i) {
//             auto val = poly.GetElementAtIndex(i);
//             for (size_t j = 0; j < val.GetLength(); ++j) {
//                 encryptedDataSS << std::setw(2) << val[j].ConvertToInt();
//             }
//         }
//     }
//     std::string encryptedDataString = encryptedDataSS.str();

//     // Output the secret key
//     std::stringstream ss;
//     ss << keys.secretKey;

//     return {decryptedHashString, ss.str(), encryptedDataString};
// }

// int main(int argc, char* argv[]) {
//     if (argc != 2) {
//         std::cerr << "Usage: " << argv[0] << " <poseidon_hash>" << std::endl;
//         return 1;
//     }

//     std::string poseidonHash = argv[1];
//     auto [decryptedHashString, secretKey, encryptedDataString] = encryptPoseidonHash(poseidonHash);

//     std::cout << "Original Poseidon hash: " << poseidonHash << std::endl;
//     std::cout << "Decrypted Poseidon hash: " << decryptedHashString << std::endl;
//     std::cout << "Secret Key: " << secretKey << std::endl;
//     std::cout << "Encrypted Data: " << encryptedDataString << std::endl;

//     return 0;
// }







































