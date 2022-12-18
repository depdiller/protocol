package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encryption"
	"flag"
	"fmt"
	"generator"
	"hashing"
	"log"
	"math"
	"os"
	"strings"
	"time"
	"verification"
)

func main() {
	pathFile := flag.String("f", "",
		"Path to file")
	verbose := flag.Bool("v", false,
		"Verbose mode")
	flag.Parse()
	index := strings.Index(*pathFile, ".enc")
	if index == -1 {
		log.Fatal("invalid file extension")
	}
	res, err := verification.Verify(pathFile)
	if err != nil {
		log.Fatal(err.Error())
	}
	if res == false {
		log.Fatal("invalid file" + err.Error())
	}
	fmt.Println("Valid file!")
	Crack(pathFile, *verbose)
}

func Crack(pathFile *string, verbose bool) {
	data, err := os.ReadFile(*pathFile)
	if err != nil {
		log.Fatal(err)
	}
	var hashAlgo string
	switch data[3] {
	case 0:
		hashAlgo = hashing.Md5
	case 1:
		hashAlgo = hashing.Sha1
	default:
		log.Fatal("incorrect hash function")
	}

	var encAlgo string
	switch data[4] {
	case 0:
		encAlgo = encryption.Des3
	case 1:
		encAlgo = encryption.Aes128
	case 2:
		encAlgo = encryption.Aes192
	case 3:
		encAlgo = encryption.Aes256
	default:
		log.Fatal("incorrect encryption algorithm")
	}

	start := 5
	nonce := data[start : encryption.NonceSize+start]
	start += encryption.NonceSize
	var iv []byte
	if data[4] == 0 {
		iv = data[start : start+encryption.DesIvSize]
		start += encryption.DesIvSize
	} else {
		iv = data[start : start+encryption.AesIvSize]
		start += encryption.AesIvSize
	}
	ciphertext := data[start:]
	if verbose {
		fmt.Printf("Hash function: %s\nEncryption algorithm: %s\n"+
			"Nonce: %s\nIV: %s\nCiphertext: %s\n", hashAlgo, encAlgo, hex.EncodeToString(nonce),
			hex.EncodeToString(iv), hex.EncodeToString(ciphertext))
	}

	dotIndex := strings.Index(*pathFile, ".enc")
	passwordFromFile := (*pathFile)[dotIndex-8 : dotIndex]
	passwordFromFileBytes, _ := hex.DecodeString(passwordFromFile)
	var password []byte
	var i uint32
	fmt.Println("Cracking...")
	var batch uint32 = 0
	password = make([]byte, 4)
	binary.BigEndian.PutUint32(password, 0)
	prev := make([]byte, len(password))
	copy(prev, password)
	begin := time.Now()
	for i = 0; i < math.MaxUint32; i++ {
		binary.BigEndian.PutUint32(password, i)
		eq := bytes.Equal(password, passwordFromFileBytes)
		if verbose && i == (batch+65535) {
			logStr := fmt.Sprintf("%s - %s |", hex.EncodeToString(prev), hex.EncodeToString(password))
			timeTrack(begin, logStr)
			batch += 65535
			copy(prev, password)
			begin = time.Now()
		}
		if eq {
			hmac, err := hashing.GetHmac(&hashAlgo, password)
			if err != nil {
				log.Fatal(err.Error())
			}
			encKey, err1 := hashing.GenerateKeyForEncryption(hmac, nonce, &encAlgo)
			if err1 != nil {
				log.Fatal(err1.Error())
			}
			decBlockMode, _ := encryption.GetDecrypter(&encAlgo, encKey, iv)
			gen := generator.Generator{
				EncryptionKey:       encKey,
				Iv:                  iv,
				DecryptBlockMode:    decBlockMode,
				Nonce:               nonce,
				EncryptionAlgorithm: &encAlgo,
				HashAlgorithm:       &hashAlgo}
			text := gen.Decrypt(ciphertext)
			fmt.Printf("Found: %s\nPlaintext: %s",
				hex.EncodeToString(password),
				hex.EncodeToString(text))
			return
		}
	}
}

func timeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	fmt.Printf("%s took %dns\n", name, elapsed.Nanoseconds())
}
