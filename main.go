package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func root(args []string) error {
	if len(args) < 1 {
		return errors.New("kau harus ngasi sub-command wak, coba kau jalankan 'asu tolonglah' untuk liat contoh")
	}

	subcommand := os.Args[1]

	switch subcommand {
	case "tolonglah":
		fmt.Println("ini contoh sub-command-nya wak:")
		fmt.Println("asu enkriplah <--- untuk bantu kau enkrip teks")
		fmt.Println("asu dekriplah <--- untuk bantu kau dekrip teks")
		return nil
	case "enkriplah":
		fmt.Println("masukkan teks yang mau kau enkrip wak:")
		reader := bufio.NewReader(os.Stdin)
		text, _ := reader.ReadString('\n')

		fmt.Println("masukkan password untuk enkrip teks-nya wak:")
		password, _ := reader.ReadString('\n')

		ciphertext := encrypt([]byte(text), password)
		fmt.Printf("ini hasilnya wak: %x\n", ciphertext)
		return nil
	case "dekriplah":
		fmt.Println("masukkan teks yang ingin kau dekrip wak:")
		reader := bufio.NewReader(os.Stdin)
		text, _ := reader.ReadString('\n')

		fmt.Println("masukkan password untuk dekrip teks-nya wak:")
		password, _ := reader.ReadString('\n')

		hexText, _ := hex.DecodeString(text)

		plaintext := decrypt(hexText, password)
		fmt.Printf("ini hasilnya wak: %s\n", plaintext)
		return nil
	default:
		return errors.New("aku ga ngerti sub-command itu wak, coba kau jalankan 'asu tolonglah' untuk liat contoh")
	}

}

func main() {
	err := root(os.Args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
