#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <algorithm>
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

// Helper function to convert ciphertext to a hexadecimal string
std::string ciphertextToHexString(const Ciphertext<DCRTPoly>& ciphertext) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto& poly : ciphertext->GetElements()) {
        for (size_t i = 0; i < poly.GetNumOfElements(); ++i) {
            auto val = poly.GetElementAtIndex(i);
            for (size_t j = 0; j < val.GetLength(); ++j) {
                ss << std::setw(2) << val[j].ConvertToInt();
            }
        }
    }
    return ss.str();
}

// Function to encrypt a given Poseidon hash and return the secret key, original encrypted data, and updated encrypted data
std::tuple<std::string, std::string, std::string> encryptPoseidonHash(const std::string& poseidonHash) {
    // Initialize the context for BFV scheme
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(1);
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKESchemeFeature::PKE);
    cc->Enable(PKESchemeFeature::LEVELEDSHE);

    // Generate keys
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    // Convert the hexadecimal string to a vector of integers
    std::vector<int64_t> hashVec = hexStringToVector(poseidonHash.substr(2));

    // Encrypt the hash
    Plaintext plaintext = cc->MakePackedPlaintext(hashVec);
    auto ciphertext = cc->Encrypt(keys.publicKey, plaintext);

    // Convert encrypted data to hexadecimal string
    std::string encryptedDataString = ciphertextToHexString(ciphertext);

    // Create a plaintext with the value 1000
    std::vector<int64_t> addValue(hashVec.size(), 1000);
    Plaintext addPlaintext = cc->MakePackedPlaintext(addValue);

    // Perform homomorphic addition
    auto updatedCiphertext = cc->EvalAdd(ciphertext, addPlaintext);

    // Convert updated encrypted data to hexadecimal string
    std::string updatedEncryptedDataString = ciphertextToHexString(updatedCiphertext);

    // Output the secret key
    std::stringstream ss;
    ss << keys.secretKey;

    return {ss.str(), encryptedDataString, updatedEncryptedDataString};
}


int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <poseidon_hash>" << std::endl;
        return 1;
    }

    std::string poseidonHash = argv[1];
    auto [secretKey, encryptedDataString, updatedEncryptedDataString] = encryptPoseidonHash(poseidonHash);

    std::cout << "Updated Encrypted Data: " << updatedEncryptedDataString << std::endl;
    std::cout << "Encrypted Data: " << encryptedDataString << std::endl;
    std::cout << "Secret Key: " << secretKey << std::endl;

    if (encryptedDataString == updatedEncryptedDataString) {
        std::cout << "Original and updated encrypted data are equal." << std::endl;
    } else {
        std::cout << "Original and updated encrypted data are not equal." << std::endl;
    }

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

// // Function to encrypt a given Poseidon hash and return the secret key and encrypted data
// std::tuple<std::string, std::string> encryptPoseidonHash(const std::string& poseidonHash) {
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

//     return {ss.str(), encryptedDataString};
// }

// int main(int argc, char* argv[]) {
//     if (argc != 2) {
//         std::cerr << "Usage: " << argv[0] << " <poseidon_hash>" << std::endl;
//         return 1;
//     }

//     std::string poseidonHash = argv[1];
//     auto [secretKey, encryptedDataString] = encryptPoseidonHash(poseidonHash);

//     std::cout << "Secret Key: " << secretKey << std::endl;
//     std::cout << "Encrypted Data: " << encryptedDataString << std::endl;

//     return 0;
// }









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

// // Function to encrypt a given Poseidon hash and return the secret key and encrypted data
// std::tuple<std::string, std::string> encryptPoseidonHash(const std::string& poseidonHash) {
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

//     return {ss.str(), encryptedDataString};
// }

// int main(int argc, char* argv[]) {
//     if (argc != 2) {
//         std::cerr << "Usage: " << argv[0] << " <poseidon_hash>" << std::endl;
//         return 1;
//     }

//     std::string poseidonHash = argv[1];
//     auto [secretKey, encryptedDataString] = encryptPoseidonHash(poseidonHash);

//     std::cout << "Secret Key: " << secretKey << std::endl;
//     std::cout << "Encrypted Data: " << encryptedDataString << std::endl;

//     return 0;
// }










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
















// #include <iostream>
// #include <string>
// #include <vector>
// #include <cstdint>
// #include <iomanip>
// #include <sstream>
// #include <algorithm>
// #include <openssl/bio.h>
// #include <openssl/evp.h>
// #include <openssl/buffer.h>
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

// // Helper function to base64 encode a string
// std::string base64Encode(const std::string& input) {
//     BIO *bio, *b64;
//     BUF_MEM *bufferPtr;
//     b64 = BIO_new(BIO_f_base64());
//     bio = BIO_new(BIO_s_mem());
//     bio = BIO_push(b64, bio);
//     BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
//     BIO_write(bio, input.c_str(), input.length());
//     BIO_flush(bio);
//     BIO_get_mem_ptr(bio, &bufferPtr);
//     BIO_set_close(bio, BIO_NOCLOSE);
//     BIO_free_all(bio);
//     return std::string(bufferPtr->data, bufferPtr->length);
// }

// // Helper function to base64 decode a string
// std::string base64Decode(const std::string& input) {
//     BIO *bio, *b64;
//     char* buffer = (char*)malloc(input.length());
//     memset(buffer, 0, input.length());
//     b64 = BIO_new(BIO_f_base64());
//     bio = BIO_new_mem_buf(input.c_str(), input.length());
//     bio = BIO_push(b64, bio);
//     BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
//     int decodedSize = BIO_read(bio, buffer, input.length());
//     BIO_free_all(bio);
//     std::string output(buffer, decodedSize);
//     free(buffer);
//     return output;
// }

// // Function to encrypt a given Poseidon hash and return the secret key and encrypted data
// std::tuple<std::string, std::string> encryptPoseidonHash(const std::string& poseidonHash) {
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

//     // Serialize the secret key
//     std::stringstream ssKey;
//     Serial::Serialize(keys.secretKey, ssKey, SerType::BINARY);
//     std::string secretKeyStr = ssKey.str();

//     // Serialize the encrypted data
//     std::stringstream ssEncryptedData;
//     Serial::Serialize(ciphertext, ssEncryptedData, SerType::BINARY);
//     std::string encryptedDataStr = ssEncryptedData.str();

//     // Base64 encode the serialized strings
//     std::string secretKeyBase64 = base64Encode(secretKeyStr);
//     std::string encryptedDataBase64 = base64Encode(encryptedDataStr);

//     return {secretKeyBase64, encryptedDataBase64};
// }

// // Function to decrypt a given ciphertext and return the decrypted value
// int64_t decryptValue(const Ciphertext<DCRTPoly>& ciphertext, CryptoContext<DCRTPoly> cc, const PrivateKey<DCRTPoly>& secretKey) {
//     Plaintext plaintext;
//     cc->Decrypt(secretKey, ciphertext, &plaintext);
//     return plaintext->GetPackedValue()[0];
// }

// // Function to add a value to an encrypted ciphertext without decrypting
// std::string addEncryptedValue(const std::string& encryptedDataStr, CryptoContext<DCRTPoly>& cc, PrivateKey<DCRTPoly>& secretKey, int64_t valueToAdd) {
//     // Deserialize the ciphertext
//     std::stringstream ss(encryptedDataStr);
//     Ciphertext<DCRTPoly> encryptedAmount;
//     Serial::Deserialize(encryptedAmount, ss, SerType::BINARY);

//     // Create a plaintext for the amount to add
//     Plaintext plainAmountToAdd = cc->MakePackedPlaintext({valueToAdd});

//     // Homomorphically add the value to the encrypted amount
//     Ciphertext<DCRTPoly> updatedEncryptedAmount = cc->EvalAdd(encryptedAmount, plainAmountToAdd);

//     // Serialize the updated ciphertext
//     std::stringstream updatedEncryptedDataSS;
//     Serial::Serialize(updatedEncryptedAmount, updatedEncryptedDataSS, SerType::BINARY);

//     return updatedEncryptedDataSS.str();
// }

// int main(int argc, char* argv[]) {
//     if (argc != 2) {
//         std::cerr << "Usage: " << argv[0] << " <poseidon_hash>" << std::endl;
//         return 1;
//     }

//     std::string poseidonHash = argv[1];
//     auto [secretKeyBase64, encryptedDataBase64] = encryptPoseidonHash(poseidonHash);

//     std::cout << "Secret Key (Base64): " << secretKeyBase64 << std::endl;
//     std::cout << "Encrypted Data (Base64): " << encryptedDataBase64 << std::endl;

//     // Initialize the context for BFV scheme
//     CCParams<CryptoContextBFVRNS> parameters;
//     parameters.SetPlaintextModulus(65537);  // Adjust the plaintext modulus
//     parameters.SetMultiplicativeDepth(1);
//     auto cc = GenCryptoContext(parameters);
//     cc->Enable(PKESchemeFeature::PKE);
//     cc->Enable(PKESchemeFeature::LEVELEDSHE);

//     // Decode the base64-encoded secret key and encrypted data back to binary
//     std::string secretKeyStr = base64Decode(secretKeyBase64);
//     std::string encryptedDataStr = base64Decode(encryptedDataBase64);

//     // Deserialize the secret key
//     std::stringstream ssKey(secretKeyStr);
//     PrivateKey<DCRTPoly> secretKey;
//     Serial::Deserialize(secretKey, ssKey, SerType::BINARY);

//     // Add 1000 to the encrypted amount
//     std::string updatedEncryptedDataStr = addEncryptedValue(encryptedDataStr, cc, secretKey, 1000);

//     // Compare encrypted data before and after addition
//     if (encryptedDataBase64 == base64Encode(updatedEncryptedDataStr)) {
//         std::cout << "Encrypted data before and after addition is equal." << std::endl;
//     } else {
//         std::cout << "Encrypted data before and after addition is NOT equal." << std::endl;
//     }

//     // Deserialize the original and updated encrypted data
//     std::stringstream ssOriginal(encryptedDataStr);
//     Ciphertext<DCRTPoly> encryptedAmount;
//     Serial::Deserialize(encryptedAmount, ssOriginal, SerType::BINARY);

//     std::stringstream ssUpdated(updatedEncryptedDataStr);
//     Ciphertext<DCRTPoly> updatedEncryptedAmount;
//     Serial::Deserialize(updatedEncryptedAmount, ssUpdated, SerType::BINARY);

//     // Decrypt the original and updated amounts
//     int64_t originalAmount = decryptValue(encryptedAmount, cc, secretKey);
//     int64_t updatedAmount = decryptValue(updatedEncryptedAmount, cc, secretKey);

//     std::cout << "Original Amount: " << originalAmount << std::endl;
//     std::cout << "Updated Amount: " << updatedAmount << std::endl;

//     // Verify the updated amount is correct
//     if (updatedAmount == originalAmount + 1000) {
//         std::cout << "Homomorphic addition is correct." << std::endl;
//     } else {
//         std::cout << "Homomorphic addition is NOT correct." << std::endl;
//     }

//     return 0;
// }
