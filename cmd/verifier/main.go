package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
	"verification"
)

func main() {
	pathFile := flag.String("f", "",
		"Path to file")
	flag.Parse()
	index := strings.Index(*pathFile, ".enc")
	if index == -1 {
		log.Fatal("invalid file extension")
	}
	res, err := verification.Verify(pathFile)
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println(res)
}
