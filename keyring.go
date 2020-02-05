package memberlist

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"sync"

	"golang.org/x/crypto/sha3"
)

// Keyring holds all the keys / keying material needed for encryption/decryption
type Keyring struct {
	// stage 1 KDF is used for obtaining KEK
	s1kdf sha3.ShakeHash

	// kdks holds the relevant set of KEKs dervied using s1kdf
	kdks [][]byte

	// current salt, generated randomly
	salt []byte

	// The keyring lock is used while performing IO operations on the keyring.
	l sync.Mutex
}

// Init allocates substructures
func (k *Keyring) init() error {
	k.kdks = make([][]byte, 0)
	k.s1kdf = sha3.NewShake256()
	k.salt = make([]byte, sha256.Size)
	_, err := io.ReadFull(rand.Reader, k.salt)
	return err
}

// Absorb will feed the master keying material to s1kdf
func (k *Keyring) absorb(mkm []byte) error {
	k.l.Lock()
	defer k.l.Unlock()
	_, err := k.s1kdf.Write(mkm)
	return err
}

// Fillkeks will squeeze s1kdf till current kek-id is reached
func (k *Keyring) fillkeks(currKekID uint16) error {
	k.l.Lock()
	defer k.l.Unlock()
	for i := uint16(len(k.kdks)); i <= currKekID; i++ {
		kek := make([]byte, 64)
		_, err := io.ReadFull(k.s1kdf, kek)
		if err != nil {
			return err
		}
		k.kdks = append(k.kdks, kek)
	}
	return nil
}

// GetKDK will return the KEK for given kek-id
// if keks doesn't have the KEK, it is filled
func (k *Keyring) GetKDK(kdkID uint16) []byte {
	err := k.fillkeks(kdkID)
	if err != nil {
		return nil
	}
	k.l.Lock()
	defer k.l.Unlock()
	return k.kdks[kdkID]
}

// Salt will return the current salt
func (k *Keyring) Salt() []byte {
	k.l.Lock()
	defer k.l.Unlock()
	return k.salt
}

// KDK will return latest Key Deriving Key and its id for encryption
func (k *Keyring) KDK() ([]byte, uint16) {
	k.l.Lock()
	defer k.l.Unlock()
	id := uint16(len(k.kdks) - 1)
	return k.kdks[id], id
}

// Resalt will re-init salt
func (k *Keyring) Resalt() error {
	k.l.Lock()
	defer k.l.Unlock()
	_, err := io.ReadFull(rand.Reader, k.salt)
	return err
}

// ChangeKDK will create a new KDK and use that here on
func (k *Keyring) ChangeKDK() error {
	k.l.Lock()
	defer k.l.Unlock()
	kek := make([]byte, 64)
	_, err := io.ReadFull(k.s1kdf, kek)
	if err != nil {
		return err
	}
	k.kdks = append(k.kdks, kek)
	return nil
}

// NewKeyring constructs a Keyring. The keyring absorbs the master
// keying material and can hold upto current kek-id key encryption keys
// and also holds current salt.
func NewKeyring(mkm []byte, currKdkID uint16) (*Keyring, error) {
	keyring := &Keyring{}
	err := keyring.init()
	if err != nil {
		return nil, err
	}
	err = keyring.absorb(mkm)
	if err != nil {
		return nil, err
	}
	err = keyring.fillkeks(currKdkID)
	if err != nil {
		return nil, err
	}
	return keyring, nil
}
