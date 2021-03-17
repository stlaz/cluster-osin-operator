package webhookcerts

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"time"

	certapiv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	certv1informers "k8s.io/client-go/informers/certificates/v1"
	corev1informers "k8s.io/client-go/informers/core/v1"
	certv1client "k8s.io/client-go/kubernetes/typed/certificates/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	certv1listers "k8s.io/client-go/listers/certificates/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	csrName        = "system:openshift:openshift-authenticator"
	certSecretName = "openshift-authenticator-certs"
)

type webhookAuthenticatorCertRequester struct {
	operatorClient v1helpers.OperatorClient

	csrClient certv1client.CertificateSigningRequestInterface
	csrLister certv1listers.CertificateSigningRequestLister

	secretClient corev1client.SecretInterface
	secretLister corev1listers.SecretLister
}

// NewWebhookAuthenticatorCertRequester creates a controller that creates a request
// to the CSR API for a client certificate to be used by the kube-apiserver when
// it's requesting token reviews from the oauth-apiserver
func NewWebhookAuthenticatorCertRequester(
	operatorClient v1helpers.OperatorClient,
	csrClient certv1client.CertificateSigningRequestInterface,
	csrInformers certv1informers.CertificateSigningRequestInformer,
	secretClient corev1client.SecretInterface,
	secretInformers corev1informers.SecretInformer,
	eventsRecorder events.Recorder,
) factory.Controller {
	c := &webhookAuthenticatorCertRequester{
		operatorClient: operatorClient,

		csrClient: csrClient,
		csrLister: csrInformers.Lister(),

		secretClient: secretClient,
		secretLister: secretInformers.Lister(),
	}

	return factory.New().
		WithSync(c.syncWithConditions).
		WithSyncDegradedOnError(operatorClient).
		WithInformers(operatorClient.Informer()).
		WithFilteredEventsInformers(nameFilter(csrName), csrInformers.Informer()).
		WithFilteredEventsInformers(nameFilter(certSecretName), secretInformers.Informer()).
		ToController("WebhookAuthenticatorCertRequester", eventsRecorder.WithComponentSuffix("webhook-authenticator-cert-requester"))
}

func (c *webhookAuthenticatorCertRequester) syncWithConditions(ctx context.Context, syncCtx factory.SyncContext) error {
	progressing, err := c.sync(ctx, syncCtx)

	if progressing != nil {
		var progressingText string
		progressingStatus := operatorv1.ConditionFalse
		progressingReason := "CertificateAvailable"
		if *progressing {
			progressingText = "waiting for CSR to be signed"
			progressingStatus = operatorv1.ConditionTrue
			progressingReason = "WaitingForCertificate"
		}

		_, _, statusErr := v1helpers.UpdateStatus(c.operatorClient,
			v1helpers.UpdateConditionFn(operatorv1.OperatorCondition{
				Type:    "AuthenticatorCSRProgressing",
				Status:  progressingStatus,
				Reason:  progressingReason,
				Message: progressingText,
			}))

		if statusErr != nil {
			if err != nil {
				klog.Error("failed to update operator status: %v", statusErr)
				return err
			}
			return statusErr
		}
	}

	return err
}

func (c *webhookAuthenticatorCertRequester) sync(ctx context.Context, syncCtx factory.SyncContext) (progressing *bool, err error) {
	key, cert, keyRotated, err := c.getKeyCertFromSecret(ctx)
	if err != nil {
		return nil, err
	}

	if keyRotated {
		if err := c.resubmitCSR(ctx, key); err != nil {
			return nil, err
		}
		return pbool(true), nil
	}

	if cert != nil {
		// check that the certificate is not expiring
		certValidityDuration := cert.NotAfter.Sub(cert.NotBefore)
		if time.Now().Before(cert.NotBefore.Add(time.Duration(0.8 * float64(certValidityDuration)))) {
			return pbool(false), nil
		}

		expiryMsg := fmt.Sprintf("the authenticator's certificate is almost expired (%s), will schedule a new CSR creation", cert.NotAfter.String())
		syncCtx.Recorder().Eventf("ClientCertExpiringSoon", expiryMsg)
		klog.V(5).Infof(expiryMsg)

		// delete the cert/key secret and schedule a new sync
		if err := c.secretClient.Delete(ctx, certSecretName, metav1.DeleteOptions{}); err != nil {
			return nil, err
		}
		return nil, factory.SyntheticRequeueError
	}

	// either we don't have a cert yet or it's almost expired
	csrObj, err := c.csrLister.Get(csrName)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}

	if csrObj != nil {
		if len(csrObj.Status.Conditions) == 0 {
			return pbool(true), nil
		}

		for _, cond := range csrObj.Status.Conditions {
			switch cond.Type {
			case certapiv1.CertificateDenied, certapiv1.CertificateFailed:
				if cond.Status == corev1.ConditionTrue {
					syncCtx.Recorder().Eventf("CSRFailure", "previous CSR got denied or it otherwise failed: {%s - %s: %s}", cond.Type, cond.Reason, cond.Message)
					klog.Warning("the previous CSR got denied or it otherwise failed: %v", cond)
					if err := c.resubmitCSR(ctx, key); err != nil {
						return nil, err
					}
					return pbool(true), nil
				}
			}
		}

		for _, cond := range csrObj.Status.Conditions {
			if cond.Type == certapiv1.CertificateApproved && cond.Status == corev1.ConditionTrue {
				csrCert := csrObj.Status.Certificate
				if len(csrCert) == 0 {
					return pbool(true), nil
				}
				certSecret, err := c.secretLister.Secrets("openshift-oauth-apiserver").Get(certSecretName)
				if err != nil {
					return nil, err
				}
				certSecret.Data["tls.crt"] = csrCert
				_, err = c.secretClient.Update(ctx, certSecret, metav1.UpdateOptions{})
				if err != nil {
					return nil, err
				}
				// we've got the cert, stop progressing
				return pbool(false), nil
			}
		}

		// no conditions with "True" status
		return pbool(true), nil

	}

	if err = c.resubmitCSR(ctx, key); err != nil {
		return nil, err
	}

	return pbool(true), nil
}

func (c *webhookAuthenticatorCertRequester) getKeyCertFromSecret(ctx context.Context) (key *rsa.PrivateKey, cert *x509.Certificate, keyRotated bool, err error) {
	certSecret, err := c.secretLister.Secrets("openshift-oauth-apiserver").Get(certSecretName)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, nil, false, err
	}

	var keyPEM []byte
	if certSecret != nil {
		keyPEM = certSecret.Data["tls.key"]
	}
	if len(keyPEM) > 0 {
		key, err = pemDecodeRSAPrivate(keyPEM)
		if err != nil {
			klog.Error("failed to decode the private key used for the openshift-authenticator, new key will be generated: %v", err)
			// delete the secret and regenerate it in the next step with a new key
			err = c.secretClient.Delete(ctx, certSecretName, metav1.DeleteOptions{})
			if err != nil {
				return nil, nil, false, err
			}
		}
	}
	if key == nil {
		key, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, false, fmt.Errorf("failed to generate a private key: %w", err)
		}
		keyPEM, err := pemEncodeRSAPrivate(key)
		if err != nil {
			return nil, nil, false, err
		}

		if err := c.secretClient.Delete(ctx, certSecretName, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return nil, nil, false, err
		}

		_, err = c.secretClient.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: certSecretName,
			},
			Data: map[string][]byte{
				"tls.key": keyPEM,
			},
		}, metav1.CreateOptions{})

		return key, nil, true, err
	}

	certPEM := certSecret.Data["tls.crt"]
	if len(certPEM) > 0 {
		cert, err = pemDecodeCert(certPEM)

		// delete tls.crt if it's malformed or its pub key does not match the private key
		var deleteCert bool
		if err != nil {
			klog.Error("failed to decode the certificate used for the openshift-authenticator, new certificate will be requested: %v", err)
			deleteCert = true
		} else if !key.PublicKey.Equal(cert.PublicKey.(*rsa.PublicKey)) {
			klog.Error("the public key of the certificate used for the openshift-authenticator does not match the stored private key, new certificate will be requested: %v", err)
			deleteCert = true
		}

		if deleteCert {
			certSecretCopy := certSecret.DeepCopy()
			delete(certSecretCopy.Data, "tls.crt")
			_, err := c.secretClient.Update(ctx, certSecretCopy, metav1.UpdateOptions{})
			return key, nil, false, err
		}
	}

	return key, cert, false, nil
}

// resubmitCSR deletes the old CSR API object and creates a new one for the given key
func (c *webhookAuthenticatorCertRequester) resubmitCSR(ctx context.Context, key *rsa.PrivateKey) error {
	err := c.csrClient.Delete(ctx, csrName, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "system:serviceaccount:openshift-oauth-apiserver:openshift-authenticator"},
		},
		key,
	)
	if err != nil {
		return fmt.Errorf("failed to create a CSR: %w", err)
	}

	csrPEM, err := pemEncodeCSR(csrDER)
	if err != nil {
		return err
	}

	_, err = c.csrClient.Create(ctx,
		&certapiv1.CertificateSigningRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name: csrName,
			},
			Spec: certapiv1.CertificateSigningRequestSpec{
				Request:    csrPEM,
				SignerName: certapiv1.KubeAPIServerClientSignerName,
				Usages: []certapiv1.KeyUsage{
					certapiv1.UsageDigitalSignature,
					certapiv1.UsageKeyEncipherment,
					certapiv1.UsageClientAuth,
				},
			},
		},
		metav1.CreateOptions{},
	)

	return err
}

func nameFilter(name string) factory.EventFilterFunc {
	return func(obj interface{}) bool {
		metaObj, ok := obj.(metav1.ObjectMetaAccessor)
		if !ok {
			klog.Error("it's not a metaobj: %#v", obj)
			return false
		}
		return metaObj.GetObjectMeta().GetName() == name
	}
}

func pemEncodeCSR(csrDER []byte) ([]byte, error) {
	buffer := bytes.Buffer{}

	if err := pem.Encode(&buffer,
		&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER},
	); err != nil {
		return nil, fmt.Errorf("failed to convert DER CSR into a PEM-formatted block: %w", err)
	}

	return buffer.Bytes(), nil
}

func pemEncodeRSAPrivate(key *rsa.PrivateKey) ([]byte, error) {
	buffer := bytes.Buffer{}

	if err := pem.Encode(&buffer,
		&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)},
	); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func pemDecodeRSAPrivate(key []byte) (*rsa.PrivateKey, error) {
	keyBlock, rest := pem.Decode(key)
	if len(rest) > 0 { // we only expect a single private key here
		return nil, fmt.Errorf("found more than one PEM block in the private key string")
	}

	if keyBlock == nil {
		return nil, fmt.Errorf("no PEM data found when decoding the private key")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse a private key: %w", err)
	}

	return privKey, nil
}

func pemDecodeCert(certPEM []byte) (*x509.Certificate, error) {
	certBlock, rest := pem.Decode(certPEM)
	if len(rest) > 0 { // we only expect a single private key here
		return nil, fmt.Errorf("found more than one PEM block in the cert key string")
	}

	if certBlock == nil {
		return nil, fmt.Errorf("no PEM data found when decoding the cert")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse a certificate: %w", err)
	}

	return cert, nil
}

func pbool(b bool) *bool {
	return &b
}
