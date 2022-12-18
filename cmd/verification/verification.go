package verification

import (
	"encryption"
	"errors"
	"log"
	"os"
)

func Verify(pathFile *string) (bool, error) {
	data, err := os.ReadFile(*pathFile)
	if err != nil {
		log.Fatal(err)
	}
	enc := string(data[:3])
	if enc != "ENC" {
		return false, errors.New("incorrect file start")
	}
	if !(data[3] == 0 || data[3] == 1) {
		return false, errors.New("incorrect hash function: ")
	}
	encryptionAlgo := data[4]
	if !(encryptionAlgo == 0 || encryptionAlgo == 1 || encryptionAlgo == 2 || encryptionAlgo == 3) {
		return false, errors.New("incorrect encryption algorithm")
	}
	if encryptionAlgo == 0 {
		cipher := data[5+encryption.NonceSize+encryption.DesIvSize:]
		if len(cipher)%encryption.DesBlockSize != 0 {
			return false, errors.New("incorrect block size")
		}
	} else {
		cipher := data[5+encryption.NonceSize+encryption.AesIvSize:]
		if len(cipher)%encryption.AesBlockSize != 0 {
			return false, errors.New("incorrect block size")
		}
	}
	return true, nil
}
