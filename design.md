+----------------+       +-----------+       +---------+
|  KeyExchange   |<----->|   HKDF    |<----->|  AesGcm |
+----------------+       +-----------+       +---------+

## Class: KeyExchange

// Generates a Kyber512 keypair.
// Returns: (publicKey, secretKey)
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generate_keypair();

// Encapsulates a shared secret under peer’s public key.
// Returns: (ciphertext, sharedSecret)
std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
  encapsulate(const std::vector<uint8_t>& publicKey);

// Recovers shared secret from ciphertext and own secret key.
// Returns: sharedSecret
std::vector<uint8_t>
  decapsulate(const std::vector<uint8_t>& ciphertext,
              const std::vector<uint8_t>& secretKey);

## Class: HKDF

// Derives a key of length output_len from input keying material using HKDF-SHA256.
// Returns: derived key bytes
static std::vector<uint8_t>
  derive(const std::vector<uint8_t>& ikm,
         const std::vector<uint8_t>& salt,
         const std::vector<uint8_t>& info,
         size_t output_len);

## Class: AesGcm

// Encrypts plaintext with AES-256-GCM.
// Returns: (ciphertext, authTag)
static std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
  encrypt(const std::vector<uint8_t>& plaintext,
          const std::vector<uint8_t>& key,
          const std::vector<uint8_t>& nonce,
          const std::vector<uint8_t>& aad);

// Decrypts ciphertext + tag with AES-256-GCM.
// Returns: plaintext (throws on auth failure)
static std::vector<uint8_t>
  decrypt(const std::vector<uint8_t>& ciphertext,
          const std::vector<uint8_t>& authTag,
          const std::vector<uint8_t>& key,
          const std::vector<uint8_t>& nonce,
          const std::vector<uint8_t>& aad);

The whole VPN uses post quantum KEM, we have decided to use the Kyber 512 algorithm.

uint8_t is used as the buffer for all the vectors because its the way to represent true raw_bytes in cpp.

The encapsulation creates a ciphertext which has some hints for the shared secrets and then the decapsulates decrypts that, the shared secret will be the symmmetric AES GCM key and the authenticator tag.

HKDF stretches the raw shared secret into cryptographically independent keys. We use HKDF-SHA256 to derive two separate 32-byte keys: one for AES-256-GCM encryption and one for authentication.

AES-256-GCM provides authenticated encryption for VPN packets. The 32-byte key encrypts the payload, the 12-byte nonce ensures uniqueness, and the 16-byte authTag verifies integrity. Any modification to ciphertext or AAD causes decryption to fail.
