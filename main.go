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
)

func main() {
privateKey :=GeneratePrivateKey()
// CreateFiless()
FullRsa(privateKey)
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


func CreateFiless()  {
    pemBytes, err := os.ReadFile("gate-sap-private.pem")
if err != nil {
    fmt.Println("Error reading PEM file:", err)
    return
 
}
block, _ := pem.Decode(pemBytes)
if block == nil {
    fmt.Println("Failed to decode PEM block")
    return
}

fmt.Println(block)

pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
if err != nil {
    fmt.Println("Failed to parse RSA public key:", err)
    return
}
rsaPubKey := pubKey.(*rsa.PublicKey) // Type assertion to get rsa.PublicKey

fmt.Println(rsaPubKey)
}


func Createfile()  {
    pubDER := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
pubBlock := pem.Block{
    Type:  "PUBLIC KEY",
    Bytes: pubDER,
}

    err:= error
    
    pemFile, err = os.Create("public.pem") // Adjust filename as needed
if err != nil {
    fmt.Println("Error creating PEM file:", err)
    return
}
defer pemFile.Close()

err = pem.Encode(pemFile, &pubBlock)
if err != nil {
    fmt.Println("Error encoding PEM block:", err)
    return
}
fmt.Println("Public key saved to public.pem")
}
