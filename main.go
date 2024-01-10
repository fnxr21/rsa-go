package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

)

func main() {
    // GenerateRsaPem()
    returnMessage,_,_:=FandiFuc("testt")

	fmt.Println(returnMessage)
    // NinoFuc(ciphertext,privateKeyFromPEM)
	
}


func GenerateRsaPem()  {
    // Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating private key:", err)
		return
	}
    
	// Save private key to file
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	err = os.WriteFile("gate-sap-private.pem", privateKeyPEM, 0600)
	if err != nil {
		fmt.Println("Error saving private key to file:", err)
		return
	}

	fmt.Println("Private key saved to private.pem")

}


func FandiFuc(messageSTR string) (string,[]byte,*rsa.PrivateKey) {
    	// Load private key from file
	privateKeyFile, err := os.ReadFile("gate-sap-private.pem")
	if err != nil {
		fmt.Println("Error reading private key from file:", err)
		// return
	}
	block, _ := pem.Decode(privateKeyFile)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		fmt.Println("Error decoding private key")
		// return
	}
	privateKeyFromPEM, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("Error parsing private key:", err)
		// return
	}

	// Generate RSA public key
	publicKey := &privateKeyFromPEM.PublicKey
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	})

	fmt.Println("Public key:")
	fmt.Println(string(publicKeyPEM))

	// Encrypt a message with the public key
	message := messageSTR
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte(message))
	if err != nil {
		fmt.Println("Error encrypting message:", err)
		// return
	}

    return message,ciphertext,privateKeyFromPEM
}


func NinoFuc(ciphertext []byte,privateKeyFromPEM *rsa.PrivateKey)  {
    // Decrypt the message with the private key
	decryptedMessage, err := rsa.DecryptPKCS1v15(rand.Reader, privateKeyFromPEM, ciphertext)
	if err != nil {
		fmt.Println("Error decrypting message:", err)
		return
	}

	fmt.Println("Original message:", string(decryptedMessage))
}