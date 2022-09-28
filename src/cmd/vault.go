// Package cmd defines the command for interaction with Vault
package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/pavlo-v-chernykh/keystore-go/v4"

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

	// Debug identifies log level
	Debug = "debug"

	//Name of the store
	Name = "name"
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
	debug            bool
	name             string

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
				"ttl":         "1024",
				"ip_sans":     ipSan,
				"alt_names":   dnsSan,
			})

			if err != nil {
				log.Printf(" Error cycling the certificate: %v\n", err.Error())
			}

			//Extracting the data from the Data map
			var keyType PrivateKey = secret.Data["private_key_type"]

			// Issuing CA
			issuingCACertString := secret.Data["issuing_ca"]
			//CA Chain
			caChain := secret.Data["ca_chain"]
			//Certificate issued
			cert := secret.Data["certificate"]
			//Private Key
			privateKey := secret.Data["private_key"]
			//Serial number of the issued certificate
			serialNumber := secret.Data["serial_number"]

			if debug == true {
				log.Println(" Secret: ", secret)
				log.Printf(" \nCert: %v\n", cert)
				log.Printf(" \nExpiring: %d\n", secret.LeaseDuration)
				log.Printf(" \nIssuing CA: %s\n", issuingCACertString)
				log.Printf(" \nCA Chain: %s\n", caChain)
				log.Printf(" \nPrivate Key: %s\n", privateKey)
				log.Printf(" \nPrivate Key Type: %s\n", keyType)
			}

			log.Printf(" \nSerialNumber: %s\n", serialNumber)

			if !dryRun {
				var privateKeyBytes = []byte(fmt.Sprint(privateKey))

				log.Println(" Get the PEM block from bytes")
				decodedString, _ := pem.Decode(privateKeyBytes)

				var rootCABytes []byte = []byte(fmt.Sprint(issuingCACertString))
				rootCADecoded, _ := pem.Decode(rootCABytes)

				var certIssuedBytes []byte = []byte(fmt.Sprint(cert))
				certIssuedDecoded, _ := pem.Decode(certIssuedBytes)

				rootCACert, err := x509.ParseCertificate(rootCADecoded.Bytes)
				if err != nil {
					log.Fatalf("Error while parsing CA cert: %v", err.Error())
				}

				brokerCert, err := x509.ParseCertificate(certIssuedDecoded.Bytes)

				if err != nil {
					log.Fatalf("Error while parsing root cert: %v", err.Error())
				}

				log.Printf(" Is CA: %t\n DNS Names: %s\n Issue: %s", rootCACert.IsCA, rootCACert.DNSNames, rootCACert.Issuer)
				log.Printf(" Is CA: %t\n DNS Names: %s\n Issue: %s", brokerCert.IsCA, brokerCert.DNSNames, brokerCert.Issuer)

				//v4 API
				var keySS = keystore.New()

				//v4 API
				keySS.SetTrustedCertificateEntry("intermediate ca", keystore.TrustedCertificateEntry{
					CreationTime: time.Now(),
					Certificate: keystore.Certificate{
						Type:    "X509",
						Content: rootCACert.Raw,
					},
				})

				//Keystore needs PKCS8encoded keys
				keyPKCS1, err := x509.ParsePKCS1PrivateKey(decodedString.Bytes)
				if err != nil {
					log.Fatalf("Error while getting PKCS8Key: %v", err)
				}

				pkcs8key, err := x509.MarshalPKCS8PrivateKey(keyPKCS1)
				if err != nil {
					log.Fatalf("Error while getting PKCS8Key: %v", err)
				}

				pkEntry := keystore.PrivateKeyEntry{
					CreationTime: time.Now(),
					PrivateKey:   pkcs8key,
					CertificateChain: []keystore.Certificate{
						{
							Type:    "X509",
							Content: brokerCert.Raw,
						},
						{
							Type:    "X509",
							Content: rootCACert.Raw,
						},
					},
				}

				if err := keySS.SetPrivateKeyEntry(commonName, pkEntry, []byte(password)); err != nil {
					log.Fatal(err)
				}

				writeKeyStore(keySS, fmt.Sprintf("%s/netops-kafka.keystore.jks", keystoreLocation), []byte(password))

				if debug {
					eP, err := keySS.GetPrivateKeyEntry(commonName, []byte(password))
					if err == nil {
						log.Println(" Testing the keystore created entry succeeded")
						key, err := x509.ParsePKCS8PrivateKey(eP.PrivateKey)
						if err == nil {
							log.Printf(" Key: %v\n", key)
						}
					} else {
						log.Fatalf(" Failed testing of the private key")
					}
				}

				log.Println("Wrote the keystore at: ", fmt.Sprintf("%s/%s", keystoreLocation, name))
			}
		},
	}
)

// readKeyStore is for reading
func readKeyStore(filename string, password []byte) keystore.KeyStore {
	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	ks := keystore.New()
	if err := ks.Load(f, password); err != nil {
		log.Fatal(err) // nolint: gocritic
	}

	return ks
}

// function writeKeyStore
func writeKeyStore(ks keystore.KeyStore, filename string, password []byte) {
	f, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	err = ks.Store(f, password)
	if err != nil {
		log.Fatal(err)
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
	VaultCmd.Flags().StringVarP(&mountPath, MountPath, "M", "", "The certificate mount path on the vault server")
	VaultCmd.MarkFlagRequired(MountPath)
	VaultCmd.Flags().StringVarP(&roleName, RoleName, "R", "", "The vault role name for issuing certificates")
	VaultCmd.MarkFlagRequired(RoleName)
	VaultCmd.Flags().StringVarP(&commonName, CommonName, "C", "", "The common name to use in the certificate, default will be `hostname -f`")
	VaultCmd.MarkFlagRequired(CommonName)

	VaultCmd.Flags().StringVarP(&password, Password, "P", "changeit", "Password for the keystore")
	VaultCmd.MarkFlagRequired(password)

	VaultCmd.Flags().BoolVarP(&debug, Debug, "v", false, "If you wish to add to see more debug information.")
	VaultCmd.Flags().BoolVarP(&dryRun, DryRun, "D", false, "Dry run (Only generates certificate but does not replace it in the config.")

	VaultCmd.Flags().StringVarP(&ttlHours, TTLHours, "T", "24", "The vault role name for issuing certificates")
	VaultCmd.Flags().StringVarP(&ipSan, IPSan, "I", "", "Comma separated list of IP addresses to use in certificate SAN")
	VaultCmd.Flags().StringVarP(&dnsSan, DNSSan, "S", "", "Comma separated list of DNS addresses to use in certificate SAN")
	VaultCmd.Flags().StringVarP(&keystoreLocation, KeyStoreLocation, "L", "./", "The path to the keystore location")
	VaultCmd.Flags().StringVarP(&name, Name, "n", "kafka.netops.keystore.jks", "Optonal name of the kesytore")
}
