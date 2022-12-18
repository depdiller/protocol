package generator

import (
	"crypto/cipher"
	"encoding/hex"
	"encryption"
	"errors"
	"hashing"
	"log"
	"math/rand"
)

const (
	passwordLength = 4
	NonceSize      = 64
)

var padding []byte = []byte{0, 0, 0, 0, 0, 0, 0, 0}

type Generator struct {
	Password            string
	EncryptionKey       []byte
	Iv                  []byte
	EncryptBlockMode    cipher.BlockMode
	DecryptBlockMode    cipher.BlockMode
	Nonce               []byte
	EncryptionAlgorithm *string
	HashAlgorithm       *string
}

func SetUpGenerator(password *string, hashAlgo *string, encryptAlgo *string) Generator {
	passwordBytes, _ := hex.DecodeString(*password)
	err1 := validatePassword(passwordBytes)
	if err1 != nil {
		log.Fatal(err1.Error())
	}
	hmac, err2 := hashing.GetHmac(hashAlgo, passwordBytes)
	if err2 != nil {
		log.Fatal(err2.Error())
	}
	nonce := make([]byte, NonceSize)
	_, _ = rand.Read(nonce)
	encryptionKey, err3 := hashing.GenerateKeyForEncryption(hmac, nonce, encryptAlgo)
	if err3 != nil {
		log.Fatal(err3.Error())
	}
	ivSize, err4 := encryption.GetIvSizeByAlgorithm(encryptAlgo)
	if err4 != nil {
		log.Fatal(err4.Error())
	}
	iv := make([]byte, ivSize)
	_, _ = rand.Read(iv)
	encryptBlockMode, err5 := encryption.GetEncryptor(encryptAlgo, encryptionKey, iv)
	decryptBlockMode, err6 := encryption.GetDecrypter(encryptAlgo, encryptionKey, iv)
	if err5 != nil {
		log.Fatal(err5.Error())
	}
	if err6 != nil {
		log.Fatal(err6.Error())
	}
	return Generator{*password,
		encryptionKey,
		iv,
		encryptBlockMode,
		decryptBlockMode,
		nonce,
		encryptAlgo,
		hashAlgo}
}

func (generator *Generator) Encrypt(plaintext []byte) []byte {
	blockMode := generator.EncryptBlockMode
	plaintext = append(padding, plaintext...)
	if *generator.EncryptionAlgorithm == encryption.Des3 {
		plaintext = encryption.Pad(plaintext, encryption.DesBlockSize)
	} else if (*generator.EncryptionAlgorithm)[:3] == encryption.Aes {
		plaintext = encryption.Pad(plaintext, encryption.AesBlockSize)
	}
	var ciphertext []byte
	ciphertext = make([]byte, len(plaintext))
	blockMode.CryptBlocks(ciphertext, plaintext)
	return ciphertext
}

func (generator *Generator) Decrypt(ciphertext []byte) []byte {
	blockMode := generator.DecryptBlockMode
	var plaintext []byte
	plaintext = make([]byte, len(ciphertext))
	blockMode.CryptBlocks(plaintext, ciphertext)
	var err error
	plaintext, err = encryption.Unpad(plaintext)
	if err != nil {
		log.Fatal(err.Error())
	}
	return plaintext[len(padding):]
}

func validatePassword(password []byte) error {
	length := len(password)
	if length != passwordLength {
		return errors.New("password length must be 4 bytes")
	}
	return nil
}
