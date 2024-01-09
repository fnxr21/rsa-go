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
CreateFilePem(privateKey)
ReadFiles()
}


func GeneratePrivateKey() []byte {
// Generate the private key once and store it securely
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
	panic(err)
	}

   // Store the private key securely (e.g., in a password-protected file)
   privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
   pem.Encode(os.Stdout, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes})

   return privateKeyBytes

}

func CreateFilePem( privatekey []byte )  {
    privBlock := pem.Block{
    Type:  "RSA PRIVATE KEY",
    Bytes: privatekey,
}
pemFile, err := os.Create("private.pem") // Adjust filename as needed
if err != nil {
    fmt.Println("Error creating PEM file:", err)
    return
}
defer pemFile.Close()

err = pem.Encode(pemFile, &privBlock)
if err != nil {
    fmt.Println("Error encoding PEM block:", err)
    return
}

fmt.Println("Private key saved to private.pem")

}

func ReadFiles()  {
    pemBytes, err := os.ReadFile("private.pem")
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
    fmt.Println("Failed to parse public key:", err)
    return
}
rsaPubKey := pubKey.(*rsa.PublicKey) // For RSA public keys
message := []byte("This is a secret message")
ciphertext, err := rsa.EncryptOAEP(
    sha256.New(), // Use a secure hash function for OAEP
    rand.Reader,
    rsaPubKey,
    message,
    nil) // Additional labels for OAEP, optional
if err != nil {
    fmt.Println("Encryption error:", err)
    return
}

fmt.Println("Encrypted message:", ciphertext)


// Load the private key from its PEM file (similar steps as above)
privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes) // Assuming private key is in the same PEM file
if err != nil {
    fmt.Println("Failed to parse RSA private key:", err)
    return
}

plaintext, err := rsa.DecryptOAEP(
    sha256.New(),
    rand.Reader,
    privKey,
    ciphertext,
    nil) // Additional labels for OAEP, optional
if err != nil {
    fmt.Println("Decryption error:", err)
    return
}

fmt.Println("Decrypted message:", plaintext)

}


func generatepublic(privateKeyBytes []byte)  {

    	privateKey, err := rsa.GenerateKey(rand.Reader, 2048) //change with file 

     pem.Encode(os.Stdout, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes})




   
   // Generate a new public key each time
   publicKey := &privateKey.PublicKey
   publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
   if err != nil {
       panic(err)
   }
   pem.Encode(os.Stdout, &pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes})
 
   MakeMessage(privateKey)

}

func MakeMessage( privateKey *rsa.PrivateKey)  {

       publicKey := &privateKey.PublicKey
       // Encrypt a message using the public key
   message := []byte("This is a secret message")
   encryptedMessage, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, message, nil)
   if err != nil {
       panic(err)
   }
   fmt.Println("Encrypted message:", encryptedMessage)


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




   /// stop disini
   // Decrypt the message using the private key
   decryptedMessage, err := privateKey.Decrypt(nil, encryptedMessage, &rsa.OAEPOptions{Hash: crypto.SHA256})
   if err != nil {
       panic(err)
   }
   fmt.Println("Decrypted message:", string(decryptedMessage))
}



//ngk jelas
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

