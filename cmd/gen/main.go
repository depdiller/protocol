package main

import (
	"encoding/binary"
	"encoding/hex"
	"encryption"
	"flag"
	"fmt"
	"generator"
	"hashing"
	"log"
	"os"
	"strings"
)

func main() {
	password := flag.String("p", "",
		"Password to use in encryption")
	hashAlgorithm := flag.String("h", hashing.Md5,
		"Hashing algorithm")
	encryptionAlgorithm := flag.String("e", encryption.Aes128,
		"Encryption algorithm")
	flag.Parse()
	gen := generator.SetUpGenerator(password, hashAlgorithm, encryptionAlgorithm)

	// testing
	plaintext, _ := hex.DecodeString("abb2abab1b12332131")
	cipher := gen.Encrypt(plaintext)
	fmt.Println(hex.EncodeToString(cipher))
	text := gen.Decrypt(cipher)
	fmt.Println(hex.EncodeToString(text))

	bs := make([]byte, 4)
	pswd := "0a0b0cff"
	array, _ := hex.DecodeString(pswd)
	number := binary.BigEndian.Uint32(array)
	fmt.Println(number)
	binary.BigEndian.PutUint32(bs, number)
	fmt.Println(hex.EncodeToString(bs))
	//

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
