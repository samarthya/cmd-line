// Package cmd defines the command for interaction with Vault
package cmd

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/pavel-v-chernykh/keystore-go/v3"
	"github.com/spf13/cobra"
)

// PrivateKey represent the keystore information
type PrivateKey interface{}

const (
	//OptionVault defines the vault address.
	OptionVault = "vault"

	//Token identifies the token for authentication with the vault
	Token = "token"

	//MountPath identifies the path in the vault to invoke
	MountPath = "mountPath"

	//RoleName identifies the role used for the cert generation.
	RoleName = "roleName"

	//CommonName identifies the common name for the certificate to be used
	CommonName = "commonName"

	//DryRun flags the mode as dry run
	DryRun = "dryRun"

	//TTLHours flags the time in hours defaults to 24
	TTLHours = "ttlHours"

	//IPSan identifies the IP addresses to be used
	IPSan = "ipSan"

	//DNSSan identifies the Domain names to use
	DNSSan = "dnsSan"

	//Password identifies the keystore password
	Password = "password"

	//KeyStoreLocation identifies the loaction of the keystore
	KeyStoreLocation = "keystore"
)

var (
	vaultAddress     string
	dryRun           bool
	token            string
	roleName         string
	mountPath        string
	commonName       string
	ipSan            string
	dnsSan           string
	ttlHours         string
	password         string
	keystoreLocation string

	// VaultCmd command to interact with the vault
	VaultCmd = &cobra.Command{
		Use:        "vault",
		Aliases:    []string{"VAULT"},
		SuggestFor: []string{"Vault"},
		Short:      "Communicate with a vault instance & process",
		Long:       `Allows you to generate certificate based on communication with a vault instance.`,
		Run: func(cmd *cobra.Command, args []string) {
			config := vault.DefaultConfig()
			config.Address = vaultAddress

			// Check for errors
			client, err := vault.NewClient(config)
			if err != nil {
				log.Printf("Error initializing vault client : %v\n", err.Error())
				os.Exit(1)
			}

			//Using the root token for [now](https://www.vaultproject.io/api-docs/secret/pki#issuing-certificates)
			client.SetToken(token)
			secret, err := client.Logical().Write(fmt.Sprintf("%s/issue/%s", mountPath, roleName), map[string]interface{}{
				"common_name": commonName,
				"ttl":         ttlHours,
				"ip_sans":     ipSan,
				"alt_names":   dnsSan,
			})

			if err != nil {
				log.Printf(" Error cycling the certificate: %v\n", err.Error())
			}

			//Extracting the data from the Data map
			var keyType PrivateKey = secret.Data["private_key_type"]

			issuingCACertString := secret.Data["issuing_ca"]
			caChain := secret.Data["ca_chain"]
			privateKey := secret.Data["private_key"]
			serialNumber := secret.Data["serial_number"]

			log.Println(" Secret: ", secret)
			log.Printf(" Expiring: %d\n", secret.LeaseDuration)
			log.Printf(" Issuing CA: %s\n", issuingCACertString)
			log.Printf(" CA Chain: %s\n", caChain)
			log.Printf(" Private Key: %s\n", privateKey)
			log.Printf(" Private Key Type: %s\n", keyType)
			log.Printf(" SerialNumber: %s\n", serialNumber)

			if !dryRun {
				x509Key, err := TranslatePrivateKey(privateKey)
				if err != nil {
					log.Fatalf("Error while creating PKCS8 key: %v", err.Error())
				}

				var pCA []byte = []byte(fmt.Sprint(issuingCACertString))
				dCA, _ := pem.Decode(pCA)
				xCA, err := x509.ParseCertificate(dCA.Bytes)

				if err != nil {
					log.Fatalf("Error while parsing CA cert: %v", err.Error())
				}

				log.Printf(" Is CA: %t\n DNS Names: %s\n Issue: %s", xCA.IsCA, xCA.DNSNames, xCA.Issuer)

				// dCAChain, _ := pem.Decode([]byte(fmt.Sprint(caChain)))
				keyStoreSafe := keystore.KeyStore{
					commonName: &keystore.PrivateKeyEntry{
						Entry: keystore.Entry{
							CreationTime: time.Now(),
						},
						PrivateKey: x509Key,
					},
					"caroot": &keystore.TrustedCertificateEntry{
						Entry: keystore.Entry{
							CreationTime: time.Now(),
						},
						Certificate: keystore.Certificate{
							Type:    "X509",
							Content: xCA.Raw,
						},
					},
				}

				defer zeroing([]byte(password))
				writeKeyStore(keyStoreSafe, fmt.Sprintf("%s/netops-kafka.keystore.jks", keystoreLocation), []byte(password))
				log.Println("Wrote the keystore at: ", fmt.Sprintf("%s/netops-kafka.keystore.jks", keystoreLocation))
			}
		},
	}
)

// check does error checking
func check(e error) {
	if e != nil {
		log.Printf("error: %v", e)
	}
}

// passphraseToHash returns a hexadecimal string of an SHA1 checksumed passphrase
func passphraseToHash(pass string) (string, []byte) {
	// The salt is used as a unique string to defeat rainbow table attacks
	saltHash := md5.New()
	saltHash.Write([]byte(pass))
	saltyBytes := saltHash.Sum(nil)
	salt := hex.EncodeToString(saltyBytes)

	saltyPass := []byte(pass + salt)
	hasher := sha1.New()
	hasher.Write(saltyPass)

	hash := hasher.Sum(nil)

	return hex.EncodeToString(hash), hash
}

// encryptBytes is a function that takes a plain byte slice and a passphrase and returns an encrypted byte slice
func encryptBytes(bytesIn []byte, passphrase string) []byte {
	passHash, _ := passphraseToHash(passphrase)
	targetPassHash := passHash[0:32]

	// Create an AES Cipher
	block, err := aes.NewCipher([]byte(targetPassHash))
	check(err)

	// Create a new gcm block container
	gcm, err := cipher.NewGCM(block)
	check(err)

	// Never use more than 2^32 random nonces with a given key because of the risk of repeat.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err)
	}

	// Seal will encrypt the file using the GCM mode, appending the nonce and tag (MAC value) to the final data, so we can use it to decrypt it later.
	return gcm.Seal(nonce, nonce, bytesIn, nil)
}

// TranslatePrivateKey as PKCS8 private key
func TranslatePrivateKey(privateKey PrivateKey) ([]byte, error) {
	log.Println(" Converting to a private key representation")
	var privateKeyBytes = []byte(fmt.Sprint(privateKey))

	log.Println(" Get the PEM block from bytes")
	decodedString, _ := pem.Decode(privateKeyBytes)

	log.Println(" Parsing the RSA private key")
	ePK, err := x509.ParsePKCS1PrivateKey(decodedString.Bytes)
	if err != nil {
		log.Fatalf("Error while parsing the private key: %v", err.Error())
	}
	privateEncodedKey := new(bytes.Buffer)

	if pem.Encode(privateEncodedKey, decodedString) == nil {
		log.Println(" Encoding succeeded")
		encBytes := encryptBytes(privateEncodedKey.Bytes(), password)
		return encBytes, nil
	}

	x509Key, err := x509.MarshalPKCS8PrivateKey(ePK)
	if err != nil {
		log.Fatalf("Error while creating PKCS8 key: %v", err.Error())
	}

	return x509Key, nil
}

// TranslatePrivateKeyEncrypted Defines the password encrypted key
func TranslatePrivateKeyEncrypted(privateKey PrivateKey) ([]byte, error) {
	var ppk = []byte(fmt.Sprint(privateKey))
	decodedString, _ := pem.Decode(ppk)

	log.Println(" Parsing the RSA private key")
	pemPrivate, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", decodedString.Bytes, []byte(password), x509.PEMCipherAES128)
	if err != nil {
		log.Fatalf("Error while encrypting the private key: %v", err.Error())
	}
	return pemPrivate.Bytes, nil
}

func readKeyStore(filename string, password []byte) keystore.KeyStore {
	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	keyStore, err := keystore.Decode(f, password)
	if err != nil {
		log.Fatal(err)
	}
	return keyStore
}

func writeKeyStore(keyStore keystore.KeyStore, filename string, password []byte) {
	o, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer o.Close()
	err = keystore.Encode(o, keyStore, password)
	if err != nil {
		log.Fatal(" Error writing keystore: ", err)
	}
}

func zeroing(s []byte) {
	for i := 0; i < len(s); i++ {
		s[i] = 0
	}
}

func init() {
	cobra.EnableCommandSorting = true

	VaultCmd.Flags().StringVarP(&vaultAddress, OptionVault, "V", "", "The vault address")
	VaultCmd.MarkFlagRequired(OptionVault)
	VaultCmd.Flags().StringVarP(&token, Token, "K", "", "The access token with certificate issue authorization")
	VaultCmd.MarkFlagRequired(Token)
	VaultCmd.Flags().StringVarP(&mountPath, MountPath, "M", "", "The certificate mount path on the vault server")
	VaultCmd.MarkFlagRequired(MountPath)
	VaultCmd.Flags().StringVarP(&roleName, RoleName, "R", "", "The vault role name for issuing certificates")
	VaultCmd.MarkFlagRequired(RoleName)
	VaultCmd.Flags().StringVarP(&commonName, CommonName, "C", "", "The common name to use in the certificate, default will be `hostname -f`")
	VaultCmd.MarkFlagRequired(CommonName)

	VaultCmd.Flags().StringVarP(&password, Password, "P", "changeit", "Password for the keystore")
	VaultCmd.MarkFlagRequired(password)

	VaultCmd.Flags().BoolP(DryRun, "D", false, "Dry run (Only generates certificate but does not replace it in the config.")
	VaultCmd.Flags().StringVarP(&ttlHours, TTLHours, "T", "24", "The vault role name for issuing certificates")
	VaultCmd.Flags().StringVarP(&ipSan, IPSan, "I", "", "Comma separated list of IP addresses to use in certificate SAN")
	VaultCmd.Flags().StringVarP(&dnsSan, DNSSan, "S", "", "Comma separated list of DNS addresses to use in certificate SAN")
	VaultCmd.Flags().StringVarP(&keystoreLocation, KeyStoreLocation, "L", "./", "The path to the keystore location")

}
