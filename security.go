package memberlist

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

/*

Encrypted messages are prefixed with an encryptionVersion byte
that is used for us to be able to properly encode/decode. We
currently support the following versions:

 0 - AES-GCM 128, using PKCS7 padding
 1 - AES-GCM 128, no padding. Padding not needed, caused bloat.

*/
type encryptionVersion uint8

const (
	minEncryptionVersion encryptionVersion = 2
	maxEncryptionVersion encryptionVersion = 2
)

const (
	versionSize    = 1
	nonceSize      = 12
	tagSize        = 16
	saltSize       = sha256.Size
	kekIDSize      = 2
	maxPadOverhead = 16
	blockSize      = aes.BlockSize
)

// encryptOverhead returns the maximum possible overhead of encryption by version
func encryptOverhead(vsn encryptionVersion) int {
	switch vsn {
	case 2:
		return 29 + saltSize + kekIDSize
	default:
		panic("unsupported version")
	}
}

// encryptedLength is used to compute the buffer size needed
// for a message of given length
func encryptedLength(vsn encryptionVersion, inp int) int {
	switch vsn {
	case 2:
		return versionSize + nonceSize + inp + tagSize + kekIDSize + saltSize
	default:
		panic("unsupported version")
	}
}

// encryptPayload is used to encrypt a message after deriving a key
// from given KEK and Salt. We make use of AES in GCM mode.
// New byte buffer is the version, kek-id, salt, nonce, ciphertext and tag
func encryptPayload(vsn encryptionVersion, kr *Keyring, msg []byte, data []byte, dst *bytes.Buffer) error {
	kek, kekid := kr.KDK()
	salt := kr.Salt()

	key := hkdf.Extract(sha256.New, kek, salt)

	// Get the AES block cipher
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Get the GCM cipher mode
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return err
	}

	// Grow the buffer to make room for everything
	offset := dst.Len()
	dst.Grow(encryptedLength(vsn, len(msg)))

	// Write the encryption version
	dst.WriteByte(byte(vsn))

	// Write the kek-id
	k := make([]byte, 2)
	binary.BigEndian.PutUint16(k, kekid)
	dst.Write(k)

	// Write the salt
	dst.Write(salt)

	// Add a random nonce
	io.CopyN(dst, rand.Reader, nonceSize)
	afterNonce := dst.Len()

	// Encrypt message using GCM
	slice := dst.Bytes()[offset:]
	nonce := slice[versionSize+kekIDSize+saltSize : versionSize+nonceSize+kekIDSize+saltSize]

	out := gcm.Seal(nil, nonce, msg, data)
	// Truncate the plaintext, and write the cipher text
	dst.Truncate(afterNonce)
	dst.Write(out)

	return nil
}

// decryptMessage performs the actual decryption of ciphertext. This is in its
// own function to allow it to be called on all keys easily.
func decryptMessage(key, msg []byte, data []byte) ([]byte, error) {
	// Get the AES block cipher
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Get the GCM cipher mode
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, err
	}

	// Decrypt the message
	nonce := msg[versionSize : versionSize+nonceSize]
	ciphertext := msg[versionSize+nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, data)
	if err != nil {
		return nil, err
	}

	// Success!
	return plain, nil
}

// decryptPayload is used to decrypt a message based on its version
// for version 2, it uses the embedded kek-id to fetch KEK from keyring
// and uses embedded salt and KEK to derive key
// for other versions, it fetches the key from keyring directly
func decryptPayload(kr *Keyring, msg []byte, data []byte) ([]byte, error) {
	// Ensure we have at least one byte
	if len(msg) == 0 {
		return nil, fmt.Errorf("Cannot decrypt empty payload")
	}

	// Verify the version
	vsn := encryptionVersion(msg[0])
	if vsn != maxEncryptionVersion {
		return nil, fmt.Errorf("Unsupported encryption version %d", msg[0])
	}

	// Ensure the length is sane
	if len(msg) < encryptedLength(vsn, 0) {
		return nil, fmt.Errorf("Payload is too small to decrypt: %d", len(msg))
	}

	kekbuf := msg[versionSize : versionSize+kekIDSize]
	kekid := binary.BigEndian.Uint16(kekbuf)
	kek := kr.GetKDK(kekid)
	if kek == nil {
		return nil, fmt.Errorf("No installed keys could decrypt the message")
	}

	salt := msg[versionSize+kekIDSize : versionSize+kekIDSize+saltSize]
	key := hkdf.Extract(sha256.New, kek, salt)
	plain, err := decryptMessage(key, msg[kekIDSize+saltSize:], data)
	if err != nil {
		return nil, fmt.Errorf("No installed keys could decrypt the message")
	}
	return plain, nil
}
