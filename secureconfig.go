package secureconfig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

type SecureConfig struct {
	signingKey    *rsa.PrivateKey
	encryptionKey *rsa.PrivateKey
	secureData    *secureData
}

type secureData struct {
	Secure  *secureTuple  `json:"secure,omitempty"`
	Private *privateTuple `json:"private,omitempty"`
}

type secureTuple struct {
	Data      json.RawMessage `json:"data"`
	Signature []byte          `json:"signature"`
}

type privateTuple struct {
	EncryptedData []byte `json:"data"`
	Signature     []byte `json:"signature"`
}

func wrapPublicKey(key *rsa.PublicKey) *rsa.PrivateKey {
	if key == nil {
		return nil
	}

	return &rsa.PrivateKey{PublicKey: *key}
}

func NewSecureConfig(signingKey *rsa.PrivateKey, encryptionKey *rsa.PublicKey) *SecureConfig {
	return &SecureConfig{
		signingKey:    signingKey,
		encryptionKey: wrapPublicKey(encryptionKey),
		secureData:    &secureData{},
	}
}

func LoadSecureConfig(signingKey *rsa.PublicKey, encryptionKey *rsa.PrivateKey, source io.Reader) (*SecureConfig, error) {
	sc := &SecureConfig{
		signingKey:    wrapPublicKey(signingKey),
		encryptionKey: encryptionKey,
		secureData:    &secureData{},
	}

	dec := json.NewDecoder(source)
	err := dec.Decode(sc.secureData)
	if err != nil {
		return nil, err
	}

	if sc.secureData.Private == nil && sc.secureData.Secure == nil {
		return nil, fmt.Errorf("No secure data found")
	}

	return sc, nil
}

func (sc *SecureConfig) SetSecureData(data interface{}) error {
	var b []byte
	var err error

	// marshal it into json then out to a RawMessage to have a common format to sign
	if b, err = json.Marshal(data); err != nil {
		return err
	}

	sc.secureData.Secure = &secureTuple{}

	if err = json.Unmarshal(b, &sc.secureData.Secure.Data); err != nil {
		return err
	}

	hashed := sha256.Sum256(sc.secureData.Secure.Data)

	sig, err := rsa.SignPSS(rand.Reader, sc.signingKey, crypto.SHA256, hashed[:], nil)
	if err != nil {
		return err
	}

	sc.secureData.Secure.Signature = make([]byte, len(sig)*2)
	hex.Encode(sc.secureData.Secure.Signature, sig)

	return nil
}

func (sc *SecureConfig) GetSecureData(v interface{}) (signatureValid bool, err error) {
	sig := make([]byte, len(sc.secureData.Secure.Signature)/2)
	if _, err := hex.Decode(sig, sc.secureData.Secure.Signature); err != nil {
		return false, err
	}

	hashed := sha256.Sum256(sc.secureData.Secure.Data)

	if err := json.Unmarshal(sc.secureData.Secure.Data, v); err != nil {
		return false, err
	}

	err = rsa.VerifyPSS(&sc.signingKey.PublicKey, crypto.SHA256, hashed[:], sig, nil)
	if err == nil {
		return true, nil
	} else {
		return false, nil
	}
}

func (sc *SecureConfig) SetPrivateData(data interface{}) error {
	var b []byte
	var err error

	if b, err = json.Marshal(data); err != nil {
		return fmt.Errorf("marshal: %v: %s", err, b)
	}

	var rm json.RawMessage

	if err = json.Unmarshal(b, &rm); err != nil {
		return fmt.Errorf("unmarshal: %v", err)
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &sc.encryptionKey.PublicKey, rm, []byte("secureconfig private data"))
	if err != nil {
		return fmt.Errorf("cipher: %v", err)
	}

	sc.secureData.Private = &privateTuple{}

	sc.secureData.Private.EncryptedData = make([]byte, len(ciphertext)*2)
	hex.Encode(sc.secureData.Private.EncryptedData, ciphertext)

	hashed := sha256.Sum256(ciphertext)

	sig, err := rsa.SignPSS(rand.Reader, sc.signingKey, crypto.SHA256, hashed[:], nil)
	if err != nil {
		return fmt.Errorf("sign: %v", err)
	}

	sc.secureData.Private.Signature = make([]byte, len(sig)*2)
	hex.Encode(sc.secureData.Private.Signature, sig)

	return nil
}

func (sc *SecureConfig) GetPrivateData(v interface{}) (signatureValid bool, err error) {
	signatureValid = false

	sig := make([]byte, len(sc.secureData.Private.Signature)/2)
	if _, err = hex.Decode(sig, sc.secureData.Private.Signature); err != nil {
		return
	}

	ciphertext := make([]byte, len(sc.secureData.Private.EncryptedData)/2)
	if _, err = hex.Decode(ciphertext, sc.secureData.Private.EncryptedData); err != nil {
		return
	}

	hashed := sha256.Sum256(ciphertext)

	if err = rsa.VerifyPSS(&sc.signingKey.PublicKey, crypto.SHA256, hashed[:], sig, nil); err == nil {
		signatureValid = true
	}

	var msg []byte
	if msg, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, sc.encryptionKey, ciphertext, []byte("secureconfig private data")); err != nil {
		return false, err
	}

	err = json.Unmarshal(msg, &v)

	return
}

func (sc *SecureConfig) Save(w io.Writer) error {
	enc := json.NewEncoder(w)
	return enc.Encode(sc.secureData)
}

func (sc *SecureConfig) SavePretty(w io.Writer) error {
	b, err := json.MarshalIndent(sc.secureData, "", "  ")
	if err != nil {
		return err
	}

	if _, err = w.Write(b); err != nil {
		return err
	}

	return nil
}
