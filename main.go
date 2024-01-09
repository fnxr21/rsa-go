package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/labstack/echo/v4"
)

func main() {
    // Generate PEM file if it doesn't exist
    if err := generatePEMFileOnce(); err != nil {
        log.Fatal("Error generating PEM file:", err)
    }

    // Start Echo server
    e := echo.New()

    e.GET("/send_message", func(c echo.Context) error {
        // Load private key from PEM file
        privateKeyBytes, err := ioutil.ReadFile("private.pem")
        if err != nil {
            return c.JSON(http.StatusInternalServerError, err.Error())
        }

        privateKey, err := x509.ParsePKCS1PrivateKey(pem.Decode(privateKeyBytes).Bytes)
        if err != nil {
            return c.JSON(http.StatusInternalServerError, err.Error())
        }

        // Extract and encode public key
        publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
        if err != nil {
            return c.JSON(http.StatusInternalServerError, err.Error())
        }
        publicKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes})

		fmt.Println(publicKey)
        // ... use publicKey to encrypt message

        return c.JSON(http.StatusOK, "Public key generated and used for encryption")
    })

    e.Logger.Fatal(e.Start(":1323"))
}

func generatePEMFileOnce() error {
    // Check if PEM file already exists
    if _, err := ioutil.ReadFile("private.pem"); err == nil {
        return nil // PEM file already exists
    }

    // Generate and write PEM file
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return err
    }

    privateBlock := pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
    }

    return ioutil.WriteFile("private.pem", pem.EncodeToMemory(&privateBlock), 0600)
}
