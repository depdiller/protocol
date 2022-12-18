package main

import (
	"encryption"
	"flag"
	"generator"
	"hashing"
	"log"
	"os"
	"strings"
)

const testFilePath = "../../txt/test.txt"
const maxFileSize = 4096

func main() {
	password := flag.String("p", "",
		"Password to use in encryption")
	hashAlgorithm := flag.String("h", hashing.Md5,
		"Hashing algorithm")
	encryptionAlgorithm := flag.String("e", encryption.Aes128,
		"Encryption algorithm")
	flag.Parse()
	gen := generator.SetUpGenerator(password, hashAlgorithm, encryptionAlgorithm)

	testFile, err1 := os.Open(testFilePath)
	if err1 != nil {
		log.Fatal(err1.Error())
	}
	defer testFile.Close()
	plaintext := make([]byte, maxFileSize)
	testFile.Read(plaintext)

	cipher := gen.Encrypt(plaintext)

	fileName := strings.Join([]string{*hashAlgorithm, *encryptionAlgorithm, *password}, "_")
	f, err := os.Create(fileName + ".enc")
	if err != nil {
		log.Fatal(err.Error())
	}
	defer f.Close()

	var protocolText []byte = []byte("ENC")
	switch *hashAlgorithm {
	case hashing.Md5:
		protocolText = append(protocolText, 0)
	case hashing.Sha1:
		protocolText = append(protocolText, 1)
	}

	switch *encryptionAlgorithm {
	case encryption.Des3:
		protocolText = append(protocolText, 0)
	case encryption.Aes128:
		protocolText = append(protocolText, 1)
	case encryption.Aes192:
		protocolText = append(protocolText, 2)
	case encryption.Aes256:
		protocolText = append(protocolText, 3)
	}
	protocolText = append(protocolText, gen.Nonce...)
	protocolText = append(protocolText, gen.Iv...)
	protocolText = append(protocolText, cipher...)

	_, err = f.Write(protocolText)
	if err != nil {
		return
	}
}
