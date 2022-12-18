package hashing

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encryption"
	"errors"
	"hash"
)

const (
	Md5  = "md5"
	Sha1 = "sha1"
)

func GetHmac(algorithmName *string, password []byte) (hash.Hash, error) {
	switch *algorithmName {
	case Md5:
		return hmac.New(md5.New, password), nil
	case Sha1:
		return hmac.New(sha1.New, password), nil
	default:
		return nil, errors.New("unsupported hashing algorithm")
	}
}

func GenerateKeyForEncryption(hmac hash.Hash, nonce []byte, encryptionAlgo *string) ([]byte, error) {
	if len(nonce) != 64 {
		return nil, errors.New("nonce must be 64 bytes")
	}
	expectedKeySize, err := encryption.GetKeySizeByAlgorithm(encryptionAlgo)
	if err != nil {
		return nil, err
	}
	hmac.Write(nonce)
	keyForEncryption := hmac.Sum(nil)
	keyLen := len(keyForEncryption)
	if keyLen < expectedKeySize {
		hmac.Write(keyForEncryption)
		secondRoundMac := hmac.Sum(nil)
		keyForEncryption = append(keyForEncryption, secondRoundMac...)
	}
	keyLen = len(keyForEncryption)
	if keyLen > expectedKeySize {
		keyForEncryption = keyForEncryption[:expectedKeySize]
	}
	return keyForEncryption, nil
}
