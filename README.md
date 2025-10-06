# CAST-384 Encryption & Decryption

## 🧩 Introduction
This repository contains an implementation of an extended **CAST block cipher**, a symmetric Feistel network cipher originally designed by *Carlisle Adams* and *Stafford Tavares*.  

While CAST-128 and CAST-256 are existing standards, this project introduces a larger, more secure variant — **CAST-384**, featuring:
- A **384-bit key size**  
- A **192-bit block size**  
- A **six-stage Feistel round structure**

The implementation also includes **CTR (Counter) mode** integration, turning the cipher into a practical encryption and decryption system.

---

## ⚙️ Overview of CAST-384
CAST-384 extends the CAST-256 cipher with a wider data path and additional diffusion mechanisms:

- **Block size:** 192 bits (6 × 32-bit words)  
- **Key size:** Up to 384 bits (12 × 32-bit words)  
- **Rounds:** 12 total (6 forward + 6 inverse)  
- **Round functions (F1–F6):** Each performs unique combinations of addition, subtraction, and XOR operations  
- **S-Boxes:** Four 8-bit → 32-bit S-boxes (S1–S4) providing strong non-linearity and avalanche effects  

Each encryption round mixes data between six 32-bit blocks using unique masking and rotation keys generated from a Feistel-based **key schedule**.

Encryption and decryption are symmetric — decryption simply applies the same process with round keys in reverse order.

---

## 🔒 Counter (CTR) Mode
The cipher is wrapped in **CTR (Counter) mode**, converting it into a secure and parallelizable stream cipher.  

CTR mode encrypts a concatenation of a **nonce** and a **counter** to generate a pseudorandom keystream, which is then XORed with the plaintext.

### Key Details:
- **Nonce:** 128 bits  
- **Counter:** 64 bits  
- **Block Size:** 192 bits (nonce + counter)  
---

## 🧠 Implementation Details

### Main Classes Implemented
#### `CAST384`
Implements the CAST-384 cipher:
- `f1`–`f6`: Round functions using S-boxes, masking, and rotation.  
- `generateScheduleKeys()`: Produces key schedule constants.  
- `dodecad()`: Performs 12×32-bit Feistel-style key expansion.  
- `generateRoundKeys()`: Generates all round key pairs (Km, Kr).  
- `initialise()`: Prepares cipher with given key and schedule.  
- `hexad()` / `hexadInv()`: Forward and inverse Feistel rounds.  
- `encrypt()` / `decrypt()`: Full block encryption and decryption.

#### `CTRMode`
Implements counter mode using CAST-384:
- `initialise()`: Sets up cipher, key, and nonce.  
- `encrypt()` / `decrypt()`: XORs data with the encrypted keystream.  
- `seek()`: Adjusts the internal 64-bit counter.

### Additional Notes
- Implemented fully in **Java**.  
- Uses **Gradle** for building and testing.  
- All arrays and words use **big-endian** byte order.  
- Supports variable key and round counts for flexibility.

---

## 🚀 Performance
✅ The implementation passed all functional tests, including encryption, decryption, and key schedule validation.  
✅ It successfully **encrypted 1 GB of data in 7.496 seconds**, demonstrating excellent performance and efficiency.

---

## 🧪 Testing & Execution
The project includes comprehensive JUnit tests for:
- Round functions (F1–F6)  
- Key schedule generation  
- Hexad and inverse hexad functions  
- CTR encryption/decryption  
- Stream-mode handling for multi-block data

---

## 🧰 Project Structure

```
src/
 ├── main/java/
 │   ├── CAST384.java        # CAST-384 cipher implementation
 │   ├── CTRMode.java        # Counter mode
 │   ├── CASTCipher.java     # Abstract base class
 │   ├── Cipher.java         # Cipher interface
 │   ├── CipherMode.java     # Mode interface
 │   ├── CASTKeySet.java     # Key management helper
 │   └── HexUtils.java       # Hex conversion utilities
 └── test/java/
     ├── CAST384Tests.java
     ├── CASTKeyScheduleTests.java
     ├── CTREncryptTests.java
     ├── CTRDecryptTests.java
     └── CTRStreamTests.java
```

---
