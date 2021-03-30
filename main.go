package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"os"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	certv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	forceRenewal, _ := strconv.ParseBool(os.Getenv("FORCE_RENEWAL"))
	service := os.Getenv("SERVICE")
	namespace := os.Getenv("NAMESPACE")
	secret := os.Getenv("SECRET")
	webhook := os.Getenv("WEBHOOK")

	config, err := rest.InClusterConfig()
	if err != nil {
		log.WithError(err).Fatal("Error InClusterConfig")
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.WithError(err).Fatal("Error NewForConfig")
	}

	clientPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.WithError(err).Fatal("Error GenerateKey")
	}

	csrName := service + "." + namespace

	x509csr := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: csrName,
		},
		DNSNames: []string{
			service,
			csrName,
			service + "." + namespace + ".svc",
		},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509csr, clientPrivateKey)
	if err != nil {
		log.WithError(err).Fatal("Error CreateCertificateRequest")
	}

	log.WithField("size", len(csrBytes)).Info("Cert size")

	clientCSRPEM := new(bytes.Buffer)
	_ = pem.Encode(clientCSRPEM, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	log.WithField("pem", clientCSRPEM).Info("Cert pem")

	csrClient := clientset.CertificatesV1beta1().CertificateSigningRequests()

	csr := &certv1beta1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: csrName,
		},
		Spec: certv1beta1.CertificateSigningRequestSpec{
			Request: clientCSRPEM.Bytes(),
			Usages:  []certv1beta1.KeyUsage{certv1beta1.UsageDigitalSignature, certv1beta1.UsageKeyEncipherment, certv1beta1.UsageServerAuth},
			Groups:  []string{"system:authenticated"},
		},
	}

	log.Info("CSR Retrieving")
	csAlreadyExists, err := csrClient.Get(context.TODO(), csrName, metav1.GetOptions{})
	if err != nil {
		log.WithError(err).Warn("Ignore Error CertificateSigningRequest")
	}

	if csAlreadyExists.Status.Certificate != nil {
		log.Info("CSR Retrieved")
		certificateAlreadyCreated := csAlreadyExists.Status.Certificate
		block, _ := pem.Decode(certificateAlreadyCreated)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.WithError(err).Fatal("Error ParseCertificate")
		}

		log.Info("Certificate check NotAfter")

		validForDays := int(cert.NotAfter.Sub(time.Now()).Hours() / 24)
		log.WithFields(log.Fields{
			"days": validForDays,
		}).Info("Certificate valid for days")

		expired := validForDays <= 364 // a k8s certificate is valid for 364 days

		if expired {
			log.Info("CSR Expired")
		}

		if forceRenewal {
			log.Info("CSR forceRenewal")
		}

		if expired || forceRenewal {
			log.Info("CSR Renewal")
			log.Info("CSR Deleting")
			err = csrClient.Delete(context.TODO(), csrName, metav1.DeleteOptions{})
			if err != nil {
				log.WithError(err).Warn("Ignore Error CertificateSigningRequest")
			}

			log.Info("CSR Deleted")
		} else {
			log.Info("CSR is valid nothing to do")
			os.Exit(0)
		}
	}

	log.Info("CSR: Creating")
	csr, err = csrClient.Create(context.TODO(), csr, metav1.CreateOptions{})
	if err != nil {
		log.WithError(err).Fatal("Error CertificateSigningRequest")
	}

	log.Info("CSR Created")
	log.Info("CSR Updating")

	csr.Status.Conditions = append(csr.Status.Conditions, certv1beta1.CertificateSigningRequestCondition{
		Type:           certv1beta1.CertificateApproved,
		Message:        "cert-signer",
		LastUpdateTime: metav1.Now(),
	})

	_, err = csrClient.UpdateApproval(context.TODO(), csr, metav1.UpdateOptions{})
	if err != nil {
		log.WithError(err).Fatal("Error UpdateApproval")
	}

	log.Info("CSR Updated")

	log.Info("CSR Retrieving")
	var updatedCsr *certv1beta1.CertificateSigningRequest
	var attempt = 0
	for {
		if attempt < 3 {
			res, err := csrClient.Get(context.TODO(), csrName, metav1.GetOptions{})
			if err != nil {
				log.WithError(err).Fatal("Error CertificateSigningRequest")
			}

			updatedCsr = res
			if updatedCsr.Status.Certificate != nil {
				log.Info("Certificate Found")
				break
			}

			log.Info("Certificate not found retry after 1 sec")
			time.Sleep(1 * time.Second)
		} else {
			log.Fatal("Certificate not found after 3 attempts")
		}

		attempt += 1
	}

	log.Info("CSR Retrieved")

	clientPrivateKeyPEM := new(bytes.Buffer)
	_ = pem.Encode(clientPrivateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(clientPrivateKey),
	})

	clientCert := updatedCsr.Status.Certificate

	log.Info("Secret Updating")
	tlsSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: secret,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.key": clientPrivateKeyPEM.Bytes(),
			"tls.crt": clientCert,
		},
	}

	_, err = clientset.CoreV1().Secrets(namespace).Update(context.TODO(), tlsSecret, metav1.UpdateOptions{})
	if err != nil {
		log.WithError(err).Warn("Ignore Error Secret Update")
		log.Info("Secret Creating")
		_, err = clientset.CoreV1().Secrets(namespace).Create(context.TODO(), tlsSecret, metav1.CreateOptions{})
		if err != nil {
			log.WithError(err).Fatal("Error Create Secret")
		}

		log.Info("Secret Created")
	} else {
		log.Info("Secret Updated")
	}

	log.Info("MutatingWebhookConfigurations Retrieving")
	webHookCfg, err := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(context.TODO(), webhook, metav1.GetOptions{})
	if err != nil {
		log.WithError(err).Fatal("Error Get MutatingWebhookConfigurations")
	}

	log.Info("MutatingWebhookConfigurations Retrieved")

	data, err := ioutil.ReadFile(config.TLSClientConfig.CAFile)

	webHookCfg.Webhooks[0].ClientConfig.CABundle = data

	log.Info("MutatingWebhookConfigurations Updating")

	_, err = clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().Update(context.TODO(), webHookCfg, metav1.UpdateOptions{})
	if err != nil {
		log.WithError(err).Fatal("Error Update MutatingWebhookConfigurations")
	}

	log.Info("MutatingWebhookConfigurations Updated")
}
