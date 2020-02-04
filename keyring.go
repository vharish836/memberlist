package memberlist

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/sha3"
)

// v1keyring is the structure for older version of keyring
type v1keyring struct {
	// Keys stores the key data used during encryption and decryption. It is
	// ordered in such a way where the first key (index 0) is the primary key,
	// which is used for encrypting messages, and is the first key tried during
	// message decryption.
	keys [][]byte

	// The keyring lock is used while performing IO operations on the keyring.
	l sync.Mutex
}

// v2keyring is the structure for newer version of keyring
type v2keyring struct {
	// stage 1 KDF is used for obtaining KEK
	s1kdf sha3.ShakeHash

	// keks holds the relevant set of KEKs dervied using s1kdf
	keks [][]byte

	// current KEK ID which is used to get the index into keks
	currKekID uint16

	// current salt, generated randomly
	salt []byte

	// The keyring lock is used while performing IO operations on the keyring.
	l sync.Mutex
}

// Keyring holds all the keys / keying material needed for encryption/decryption
type Keyring struct {
	v1 *v1keyring
	v2 *v2keyring
}

// Init allocates substructures
func (k *v1keyring) init() {
	k.keys = make([][]byte, 0)
}

// Init allocates substructures
func (k *v2keyring) init() error {
	k.keks = make([][]byte, 0)
	k.s1kdf = sha3.NewShake256()
	k.salt = make([]byte, sha256.BlockSize)
	_, err := io.ReadFull(rand.Reader, k.salt)
	return err
}

// Absorb will feed the master keying material to s1kdf
func (k *v2keyring) Absorb(mkm []byte) error {
	k.l.Lock()
	defer k.l.Unlock()
	_, err := k.s1kdf.Write(mkm)
	return err
}

// Fillkeks will squeeze s1kdf till current kek-id is reached
func (k *v2keyring) Fillkeks(currKekID uint16) error {
	k.l.Lock()
	defer k.l.Unlock()
	for i := uint16(len(k.keks)); i <= currKekID; i++ {
		kek := make([]byte, 64)
		_, err := io.ReadFull(k.s1kdf, kek)
		if err != nil {
			return err
		}
		k.keks = append(k.keks, kek)
	}
	return nil
}

// GetKEK will return the KEK for given kek-id
func (k *Keyring) GetKEK(kekID uint16) []byte {
	if k.v2 == nil {
		panic("v1 keyring does not support this api")
	}
	return k.v2.GetKEK(kekID)
}

// GetKEK will return the KEK for given kek-id
// if keks doesn't have the KEK, it is filled
func (k *v2keyring) GetKEK(kekID uint16) []byte {
	err := k.Fillkeks(kekID)
	if err != nil {
		return nil
	}
	k.l.Lock()
	defer k.l.Unlock()
	return k.keks[kekID]
}

// Salt will return the current salt
func (k *Keyring) Salt() []byte {
	if k.v2 == nil {
		panic("v1 keyring does not support this api")
	}
	return k.v2.Salt()
}

// Salt will return the current salt
func (k *v2keyring) Salt() []byte {
	k.l.Lock()
	defer k.l.Unlock()
	return k.salt
}

// KEK will return latest KEK and its id for encryption
func (k *Keyring) KEK() ([]byte, uint16) {
	if k.v2 == nil {
		panic("v1 keyring does not support this api")
	}
	return k.v2.KEK()
}

// KEK will return latest KEK and its id for encryption
func (k *v2keyring) KEK() ([]byte, uint16) {
	k.l.Lock()
	defer k.l.Unlock()
	id := uint16(len(k.keks) - 1)
	return k.keks[id], id
}

// Resalt will re-init salt
func (k *Keyring) Resalt() error {
	if k.v2 == nil {
		panic("v1 keyring does not support this api")
	}
	return k.v2.Resalt()
}

// Resalt will re-init salt
func (k *v2keyring) Resalt() error {
	k.l.Lock()
	defer k.l.Unlock()
	_, err := io.ReadFull(rand.Reader, k.salt)
	return err
}

// ChangeKEK will create a new KEK and use that here on
func (k *Keyring) ChangeKEK() error {
	if k.v2 == nil {
		panic("v1 keyring does not support this api")
	}
	return k.v2.ChangeKEK()
}

// ChangeKEK will create a new KEK and use that here on
func (k *v2keyring) ChangeKEK() error {
	k.l.Lock()
	defer k.l.Unlock()
	kek := make([]byte, 64)
	_, err := io.ReadFull(k.s1kdf, kek)
	if err != nil {
		return err
	}
	k.keks = append(k.keks, kek)
	return nil
}

// NewV2Keyring constructs a V2 Keyring. The keyring absorbs the master
// keying material and can hold upto current kek-id key encryption keys
// and also holds current salt.
func NewV2Keyring(mkm []byte, currKekID uint16) (*Keyring, error) {
	keyring := &Keyring{v2: &v2keyring{}}
	err := keyring.v2.init()
	if err != nil {
		return nil, err
	}
	err = keyring.v2.Absorb(mkm)
	if err != nil {
		return nil, err
	}
	err = keyring.v2.Fillkeks(currKekID)
	if err != nil {
		return nil, err
	}
	return keyring, nil
}

// NewKeyring constructs a new container for a set of encryption keys. The
// keyring contains all key data used internally by memberlist.
//
// While creating a new keyring, you must do one of:
//   - Omit keys and primary key, effectively disabling encryption
//   - Pass a set of keys plus the primary key
//   - Pass only a primary key
//
// If only a primary key is passed, then it will be automatically added to the
// keyring. If creating a keyring with multiple keys, one key must be designated
// primary by passing it as the primaryKey. If the primaryKey does not exist in
// the list of secondary keys, it will be automatically added at position 0.
//
// A key should be either 16, 24, or 32 bytes to select AES-128,
// AES-192, or AES-256.
func NewKeyring(keys [][]byte, primaryKey []byte) (*Keyring, error) {
	keyring := &Keyring{v1: &v1keyring{}}
	keyring.v1.init()

	if len(keys) > 0 || len(primaryKey) > 0 {
		if len(primaryKey) == 0 {
			return nil, fmt.Errorf("Empty primary key not allowed")
		}
		if err := keyring.AddKey(primaryKey); err != nil {
			return nil, err
		}
		for _, key := range keys {
			if err := keyring.AddKey(key); err != nil {
				return nil, err
			}
		}
	}

	return keyring, nil
}

// Version returns the keyring version
func (k *Keyring) Version() int {
	if k.v1 == nil {
		return 2
	}
	return 1
}

// ValidateKey will check to see if the key is valid and returns an error if not.
//
// key should be either 16, 24, or 32 bytes to select AES-128,
// AES-192, or AES-256.
func ValidateKey(key []byte) error {
	if l := len(key); l != 16 && l != 24 && l != 32 {
		return fmt.Errorf("key size must be 16, 24 or 32 bytes")
	}
	return nil
}

// AddKey will install a new key on the ring. Adding a key to the ring will make
// it available for use in decryption. If the key already exists on the ring,
// this function will just return noop.
//
// key should be either 16, 24, or 32 bytes to select AES-128,
// AES-192, or AES-256.
func (k *Keyring) AddKey(key []byte) error {
	if k.v1 == nil {
		panic("v2 keyring does not support this api")
	}

	if err := ValidateKey(key); err != nil {
		return err
	}

	return k.v1.AddKey(key)
}

// Addkey will install given key on the ring
func (k *v1keyring) AddKey(key []byte) error {
	// No-op if key is already installed
	for _, installedKey := range k.keys {
		if bytes.Equal(installedKey, key) {
			return nil
		}
	}

	keys := append(k.keys, key)
	primaryKey := k.GetPrimaryKey()
	if primaryKey == nil {
		primaryKey = key
	}
	k.installKeys(keys, primaryKey)
	return nil
}

// UseKey changes the key used to encrypt messages. This is the only key used to
// encrypt messages, so peers should know this key before this method is called.
func (k *Keyring) UseKey(key []byte) error {
	if k.v1 == nil {
		panic("v2 keyring does not support this api")
	}
	return k.v1.UseKey(key)
}

// UseKey changes the primary key
func (k *v1keyring) UseKey(key []byte) error {
	for _, installedKey := range k.keys {
		if bytes.Equal(key, installedKey) {
			k.installKeys(k.keys, key)
			return nil
		}
	}
	return fmt.Errorf("Requested key is not in the keyring")
}

// RemoveKey drops a key from the keyring. This will return an error if the key
// requested for removal is currently at position 0 (primary key).
func (k *Keyring) RemoveKey(key []byte) error {
	if k.v1 == nil {
		panic("v2 keyring does not support this api")
	}
	return k.v1.RemoveKey(key)
}

// RemoveKey drops a key from the keyring
func (k *v1keyring) RemoveKey(key []byte) error {
	if bytes.Equal(key, k.keys[0]) {
		return fmt.Errorf("Removing the primary key is not allowed")
	}
	for i, installedKey := range k.keys {
		if bytes.Equal(key, installedKey) {
			keys := append(k.keys[:i], k.keys[i+1:]...)
			k.installKeys(keys, k.keys[0])
		}
	}
	return nil
}

// installKeys will take out a lock on the keyring, and replace the keys with a
// new set of keys. The key indicated by primaryKey will be installed as the new
// primary key.
func (k *v1keyring) installKeys(keys [][]byte, primaryKey []byte) {
	k.l.Lock()
	defer k.l.Unlock()

	newKeys := [][]byte{primaryKey}
	for _, key := range keys {
		if !bytes.Equal(key, primaryKey) {
			newKeys = append(newKeys, key)
		}
	}
	k.keys = newKeys
}

// GetKeys returns the current set of keys on the ring.
func (k *Keyring) GetKeys() [][]byte {
	if k.v1 == nil {
		panic("v2 keyring does not support this api")
	}
	return k.v1.GetKeys()
}

// GetKeys returns the current set of keys on the ring.
func (k *v1keyring) GetKeys() [][]byte {
	k.l.Lock()
	defer k.l.Unlock()

	return k.keys
}

// GetPrimaryKey returns the key on the ring at position 0. This is the key used
// for encrypting messages, and is the first key tried for decrypting messages.
func (k *Keyring) GetPrimaryKey() []byte {
	if k.v1 == nil {
		panic("v2 keyring does not support this api")
	}
	return k.v1.GetPrimaryKey()
}

// GetPrimaryKey returns the key on the ring at position 0
func (k *v1keyring) GetPrimaryKey() (key []byte) {
	k.l.Lock()
	defer k.l.Unlock()

	if len(k.keys) > 0 {
		key = k.keys[0]
	}
	return
}
