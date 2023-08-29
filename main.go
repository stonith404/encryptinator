package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const (
	saltSize  = 16
	keySize   = 32
	nonceSize = 12
)

func isFolder(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fileInfo.Mode().IsDir()
}

func encrypt(path string, password string) error {
	if isFolder(path) {
		return encryptFolder(path, password)
	} else {
		return encryptFile(path, password)
	}
}

func decrypt(path string, password string) error {
	if isFolder(path) {
		return decryptFolder(path, password)
	} else {
		return decryptFile(path, password)
	}
}

func encryptFolder(folder string, password string) error {
	err := filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
		if path != folder {
			if info.IsDir() {
				err := encryptFolder(path, password)
				return err
			} else {
				err := encryptFile(path, password)
				return err
			}
		}
		return nil
	})
	return err
}

func decryptFolder(folder string, password string) error {
	err := filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
		if path != folder {
			if info.IsDir() {
				err := decryptFolder(path, password)
				return err
			} else {
				err := decryptFile(path, password)
				return err
			}
		}
		return nil
	})
	return err
}

func encryptFile(filename string, password string) error {
	plaintext, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	// Generate a random salt
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	// Derive a key from the password using Argon2
	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, keySize)

	// Create a new AES-GCM cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Create a new GCM mode cipher
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Generate a random nonce
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	// Encrypt the plaintext
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	// Write the salt, nonce, and ciphertext to the output file
	outFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer outFile.Close()

	_, err = outFile.Write(salt)
	if err != nil {
		return err
	}
	_, err = outFile.Write(nonce)
	if err != nil {
		return err
	}
	_, err = outFile.Write(ciphertext)
	if err != nil {
		return err
	}

	log.Printf("File '%s' encrypted successfully.'\n", filename)
	return nil
}

func decryptFile(filename string, password string) error {
	ciphertext, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	if len(ciphertext) < saltSize+nonceSize {
		return errors.New("file doesn't seem to be encrypted")
	}

	// Extract the salt, nonce, and ciphertext from the input file
	salt := ciphertext[:saltSize]
	nonce := ciphertext[saltSize : saltSize+nonceSize]
	ciphertext = ciphertext[saltSize+nonceSize:]

	// Derive the key from the password using Argon2
	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, keySize)

	// Create a new AES-GCM cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Create a new GCM mode cipher
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Decrypt the ciphertext
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	// Write the plaintext to the output file
	outFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer outFile.Close()

	_, err = outFile.Write(plaintext)
	if err != nil {
		return err
	}

	log.Printf("File '%s' decrypted successfully\n", filename)
	return nil
}
func isWrongPassword(err error) bool {
	// Check if the error message indicates a wrong password
	if err != nil && err.Error() == "cipher: message authentication failed" {
		return true
	}
	return false
}

func main() {
	log.SetFlags(0)

	if len(os.Args) < 3 {
		log.Fatal("Usage: encryptinator [(e)ncrypt|(d)ecrypt] <file|folder>")
	}

	action := os.Args[1]
	filename := os.Args[2]

	fmt.Print("Enter password: ")
	password, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	switch action {
	case "encrypt", "e":
		fmt.Print("Re-enter password: ")
		reenteredPassword, _ := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if string(password) != string(reenteredPassword) {
			log.Fatal("Passwords don't match")
		}
		err := encrypt(filename, string(password))
		if err != nil {
			log.Fatalf("Failed to encrypt file: %v\n", err)
		}
	case "decrypt", "d":
		err := decrypt(filename, string(password))
		if err != nil {
			if isWrongPassword(err) {
				log.Fatalf("Incorrect password")
			} else {
				log.Fatalf("Failed to decrypt file '%s': %v\n", filename, err)
			}
		}
	default:
		log.Fatal("Invalid command. Please specify 'encrypt' or 'decrypt'.")
	}

	log.Println("Operation completed successfully.")
}
