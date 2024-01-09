package main

import (
	// "crypto"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"reflect"
)

func main() {
privateKey :=GeneratePrivateKey()


fmt.Println("==============================================================================")
fmt.Println(privateKey)
fmt.Println("==============================================================================")

fmt.Println(reflect.TypeOf(privateKey))
// FullRsa(privateKey)
}


func GeneratePrivateKey() *rsa.PrivateKey {
// Generate the private key once and store it securely
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
	panic(err)
	}

   // Store the private key securely (e.g., in a password-protected file)
   privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
   pem.Encode(os.Stdout, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes})

   return privateKey

}


func FullRsa(ok *rsa.PrivateKey) {
// Generate the private key once and store it securely
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    
	if err != nil {
	panic(err)
	}

   // Store the private key securely (e.g., in a password-protected file)
   privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
   pem.Encode(os.Stdout, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes})

   // Generate a new public key each time
   publicKey := &privateKey.PublicKey
   publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
   if err != nil {
       panic(err)
   }
   pem.Encode(os.Stdout, &pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes})

   // Encrypt a message using the public key
   message := []byte("This is a secret message")
   encryptedMessage, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, message, nil)
   if err != nil {
       panic(err)
   }
   fmt.Println("Encrypted message:", encryptedMessage)

   // Decrypt the message using the private key
   decryptedMessage, err := privateKey.Decrypt(nil, encryptedMessage, &rsa.OAEPOptions{Hash: crypto.SHA256})
   if err != nil {
       panic(err)
   }
   fmt.Println("Decrypted message:", string(decryptedMessage))
}