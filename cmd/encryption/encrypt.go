package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"errors"
	"log"
)

const (
	Des3         = "3des"
	Aes128       = "aes128"
	Aes192       = "aes192"
	Aes256       = "aes256"
	Aes          = "aes"
	DesBlockSize = 8
	AesBlockSize = 16
	DesIvSize    = 8
	AesIvSize    = 16
	NonceSize    = 64
)

func GetKeySizeByAlgorithm(algorithm *string) (int, error) {
	switch *algorithm {
	case Des3:
		return 24, nil
	case Aes128:
		return 16, nil
	case Aes192:
		return 24, nil
	case Aes256:
		return 32, nil
	default:
		return 0, errors.New("unsupported encryption algorithm")
	}
}

func GetIvSizeByAlgorithm(algorithm *string) (int, error) {
	if *algorithm == Des3 {
		return DesIvSize, nil
	} else if (*algorithm)[:3] == Aes {
		return AesIvSize, nil
	}
	return 0, errors.New("incorrect encryption algorithm")
}

func GetDecrypter(encryptAlgo *string, key []byte, iv []byte) (cipher.BlockMode, error) {
	var block cipher.Block
	var err error
	if *encryptAlgo == Des3 {
		block, err = des.NewTripleDESCipher(key)
		if err != nil {
			log.Fatalf("NewTripleDESCipher(%d bytes) = %s", len(key), err)
		}
	} else if (*encryptAlgo)[:3] == Aes {
		block, err = aes.NewCipher(key)
		if err != nil {
			log.Fatalf("NewCipher(%d bytes) = %s", len(key), err)
		}
	}
	return cipher.NewCBCDecrypter(block, iv), nil
}

func GetEncryptor(encryptAlgo *string, key []byte, iv []byte) (cipher.BlockMode, error) {
	var block cipher.Block
	var err error
	if *encryptAlgo == Des3 {
		block, err = des.NewTripleDESCipher(key)
		if err != nil {
			log.Fatalf("NewTripleDESCipher(%d bytes) = %s", len(key), err)
		}
	} else if (*encryptAlgo)[:3] == Aes {
		block, err = aes.NewCipher(key)
		if err != nil {
			log.Fatalf("NewCipher(%d bytes) = %s", len(key), err)
		}
	}
	return cipher.NewCBCEncrypter(block, iv), nil
}

func Pad(input []byte, blockSize int) []byte {
	r := len(input) % blockSize
	pl := blockSize - r
	for i := 0; i < pl; i++ {
		input = append(input, byte(pl))
	}
	return input
}

func Unpad(input []byte) ([]byte, error) {
	if input == nil || len(input) == 0 {
		return nil, nil
	}
	pc := input[len(input)-1]
	pl := int(pc)
	err := checkPaddingIsValid(input, pl)
	if err != nil {
		return nil, err
	}
	return input[:len(input)-pl], nil
}

func checkPaddingIsValid(input []byte, paddingLength int) error {
	if len(input) < paddingLength {
		return errors.New("invalid padding")
	}
	p := input[len(input)-(paddingLength):]
	for _, pc := range p {
		if uint(pc) != uint(len(p)) {
			return errors.New("invalid padding")
		}
	}
	return nil
}
