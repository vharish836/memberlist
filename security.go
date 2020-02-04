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
	minEncryptionVersion encryptionVersion = 0
	maxEncryptionVersion encryptionVersion = 2
)

const (
	versionSize    = 1
	nonceSize      = 12
	tagSize        = 16
	saltSize       = 64
	kekIDSize      = 2
	maxPadOverhead = 16
	blockSize      = aes.BlockSize
)

// pkcs7encode is used to pad a byte buffer to a specific block size using
// the PKCS7 algorithm. "Ignores" some bytes to compensate for IV
func pkcs7encode(buf *bytes.Buffer, ignore, blockSize int) {
	n := buf.Len() - ignore
	more := blockSize - (n % blockSize)
	for i := 0; i < more; i++ {
		buf.WriteByte(byte(more))
	}
}

// pkcs7decode is used to decode a buffer that has been padded
func pkcs7decode(buf []byte, blockSize int) []byte {
	if len(buf) == 0 {
		panic("Cannot decode a PKCS7 buffer of zero length")
	}
	n := len(buf)
	last := buf[n-1]
	n -= int(last)
	return buf[:n]
}

// encryptOverhead returns the maximum possible overhead of encryption by version
func encryptOverhead(vsn encryptionVersion) int {
	switch vsn {
	case 0:
		return 45 // Version: 1, IV: 12, Padding: 16, Tag: 16
	case 1:
		return 29 // Version: 1, IV: 12, Tag: 16
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
	case 1:
		return versionSize + nonceSize + inp + tagSize
	default:
		// Determine the padding size
		padding := blockSize - (inp % blockSize)

		// Sum the extra parts to get total size
		return versionSize + nonceSize + inp + padding + tagSize
	}
}

// encryptPayloadV2 is used to encrypt a message after deriving a key
// from given KEK and Salt. We make use of AES in GCM mode.
// New byte buffer is the version, kek-id, salt, nonce, ciphertext and tag
func encryptPayloadV2(vsn encryptionVersion, kr *Keyring, msg []byte, data []byte, dst *bytes.Buffer) error {
	if vsn < 2 {
		return encryptPayload(vsn, kr.GetPrimaryKey(), msg, data, dst)
	}

	kek, kekid := kr.KEK()
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
	nonce := slice[versionSize : versionSize+nonceSize]

	out := gcm.Seal(nil, nonce, msg, data)
	// Truncate the plaintext, and write the cipher text
	dst.Truncate(afterNonce)
	dst.Write(out)

	return nil
}

// encryptPayload is used to encrypt a message with a given key.
// We make use of AES-128 in GCM mode. New byte buffer is the version,
// nonce, ciphertext and tag
func encryptPayload(vsn encryptionVersion, key []byte, msg []byte, data []byte, dst *bytes.Buffer) error {
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

	// Add a random nonce
	io.CopyN(dst, rand.Reader, nonceSize)
	afterNonce := dst.Len()

	// Ensure we are correctly padded (only version 0)
	if vsn == 0 {
		io.Copy(dst, bytes.NewReader(msg))
		pkcs7encode(dst, offset+versionSize+nonceSize, aes.BlockSize)
	}

	// Encrypt message using GCM
	slice := dst.Bytes()[offset:]
	nonce := slice[versionSize : versionSize+nonceSize]

	// Message source depends on the encryption version.
	// Version 0 uses padding, version 1 does not
	var src []byte
	if vsn == 0 {
		src = slice[versionSize+nonceSize:]
	} else {
		src = msg
	}
	out := gcm.Seal(nil, nonce, src, data)

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

// decryptPayloadV2 is used to decrypt a message based on its version
// for version 2, it uses the embedded kek-id to fetch KEK from keyring
// and uses embedded salt and KEK to derive key
// for other versions, it fetches the key from keyring directly
func decryptPayloadV2(kr *Keyring, msg []byte, data []byte) ([]byte, error) {
	// Ensure we have at least one byte
	if len(msg) == 0 {
		return nil, fmt.Errorf("Cannot decrypt empty payload")
	}

	// Verify the version
	vsn := encryptionVersion(msg[0])
	if vsn > maxEncryptionVersion {
		return nil, fmt.Errorf("Unsupported encryption version %d", msg[0])
	}

	if vsn < 2 {
		return decryptPayload(kr.GetKeys(), msg, data)
	}

	// Ensure the length is sane
	if len(msg) < encryptedLength(vsn, 0) {
		return nil, fmt.Errorf("Payload is too small to decrypt: %d", len(msg))
	}

	kekbuf := msg[versionSize : versionSize+kekIDSize]
	kekid := binary.BigEndian.Uint16(kekbuf)
	kek := kr.GetKEK(kekid)
	if kek == nil {
		return nil, fmt.Errorf("invalid kek id: %d", kekid)
	}

	salt := msg[versionSize+kekIDSize : versionSize+kekIDSize+saltSize]
	key := hkdf.Extract(sha256.New, kek, salt)
	return decryptMessage(key, msg[kekIDSize+saltSize:], data)
}

// decryptPayload is used to decrypt a message with a given key,
// and verify it's contents. Any padding will be removed, and a
// slice to the plaintext is returned. Decryption is done IN PLACE!
func decryptPayload(keys [][]byte, msg []byte, data []byte) ([]byte, error) {
	// Ensure we have at least one byte
	if len(msg) == 0 {
		return nil, fmt.Errorf("Cannot decrypt empty payload")
	}

	// Verify the version
	vsn := encryptionVersion(msg[0])
	if vsn > maxEncryptionVersion {
		return nil, fmt.Errorf("Unsupported encryption version %d", msg[0])
	}

	// Ensure the length is sane
	if len(msg) < encryptedLength(vsn, 0) {
		return nil, fmt.Errorf("Payload is too small to decrypt: %d", len(msg))
	}

	for _, key := range keys {
		plain, err := decryptMessage(key, msg, data)
		if err == nil {
			// Remove the PKCS7 padding for vsn 0
			if vsn == 0 {
				return pkcs7decode(plain, aes.BlockSize), nil
			}
			return plain, nil
		}
	}

	return nil, fmt.Errorf("No installed keys could decrypt the message")
}
