package webhookcerts

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	certapiv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclients "k8s.io/client-go/kubernetes/fake"
	certv1listers "k8s.io/client-go/listers/certificates/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func TestCertRequester(t *testing.T) {
	testCert, testKey := testCertKeyPair(t)

	defaultCSRMatch := func(t *testing.T, csr *certapiv1.CertificateSigningRequest) {
		require.NotNil(t, csr)
		require.Equal(t, csrName, csr.Name)
		require.Equal(t, certapiv1.KubeAPIServerClientSignerName, csr.Spec.SignerName)
		require.Equal(t, "CN=system:serviceaccount:openshift-oauth-apiserver:openshift-authenticator", pemDecodeCSR(t, csr.Spec.Request).Subject.String())
	}

	renewedDefaultCSRMatch := func(t *testing.T, csr *certapiv1.CertificateSigningRequest) {
		defaultCSRMatch(t, csr)
		require.Empty(t, csr.Status.Conditions)
	}

	secretNoCertMatch := func(t *testing.T, secret *corev1.Secret) {
		require.NotNil(t, secret)
		require.Equal(t, secret.Name, certSecretName)
		require.Greater(t, len(secret.Data["tls.key"]), 0, "missing tls.key")
		require.Zero(t, len(secret.Data["tls.crt"]), "expected tls.crt to be missing")
	}

	secretFullMatch := func(t *testing.T, secret *corev1.Secret) {
		require.NotNil(t, secret)
		require.Equal(t, secret.Name, certSecretName)
		require.Greater(t, len(secret.Data["tls.key"]), 0, "missing tls.key")
		require.Greater(t, len(secret.Data["tls.crt"]), 0, "missing tls.crt")
	}

	tests := []struct {
		name                string
		csr                 *certapiv1.CertificateSigningRequest
		secretData          map[string][]byte
		expectedCSRMatch    func(t *testing.T, csr *certapiv1.CertificateSigningRequest)
		expectedSecretMatch func(t *testing.T, s *corev1.Secret)
		expectedProgressing *bool
		expectFailedEvent   bool
	}{
		{
			name:                "no csr, no secret (init phase)",
			expectedCSRMatch:    renewedDefaultCSRMatch,
			expectedSecretMatch: secretNoCertMatch,
			expectedProgressing: pbool(true),
		},
		{
			name: "no csr, secret already populated",
			secretData: map[string][]byte{
				"tls.key": testKey,
				"tls.crt": testCert,
			},
			expectedCSRMatch:    func(t *testing.T, csr *certapiv1.CertificateSigningRequest) { require.Nil(t, csr) },
			expectedSecretMatch: secretFullMatch,
			expectedProgressing: pbool(false),
		},
		{
			name: "csr approved but not yet issued",
			csr: defaultCSRWithStatus(t,
				&certapiv1.CertificateSigningRequestStatus{
					Conditions: []certapiv1.CertificateSigningRequestCondition{
						{
							Type:   certapiv1.CertificateApproved,
							Status: corev1.ConditionTrue,
						},
					},
				}),
			secretData:          map[string][]byte{"tls.key": testKey},
			expectedCSRMatch:    defaultCSRMatch,
			expectedSecretMatch: secretNoCertMatch,
			expectedProgressing: pbool(true),
		},
		{
			name: "csr approved and issued",
			csr: defaultCSRWithStatus(t,
				&certapiv1.CertificateSigningRequestStatus{
					Certificate: testCert,
					Conditions: []certapiv1.CertificateSigningRequestCondition{
						{
							Type:   certapiv1.CertificateApproved,
							Status: corev1.ConditionTrue,
						},
					},
				}),
			secretData:          map[string][]byte{"tls.key": testKey},
			expectedCSRMatch:    defaultCSRMatch,
			expectedSecretMatch: secretFullMatch,
			expectedProgressing: pbool(true),
		},
		{
			name: "csr approved and issued, but there's no key in the cert secret -> reissue the CSR",
			csr: defaultCSRWithStatus(t,
				&certapiv1.CertificateSigningRequestStatus{
					Certificate: testCert,
					Conditions: []certapiv1.CertificateSigningRequestCondition{
						{
							Type:   certapiv1.CertificateApproved,
							Status: corev1.ConditionTrue,
						},
					},
				}),
			expectedCSRMatch:    renewedDefaultCSRMatch,
			expectedSecretMatch: secretNoCertMatch,
			expectedProgressing: pbool(true),
		},
		{
			name: "signer failed to issue the certificate",
			csr: defaultCSRWithStatus(t,
				&certapiv1.CertificateSigningRequestStatus{
					Certificate: testCert,
					Conditions: []certapiv1.CertificateSigningRequestCondition{
						{
							Type:   certapiv1.CertificateFailed,
							Status: corev1.ConditionTrue,
						},
					},
				}),
			secretData:          map[string][]byte{"tls.key": testKey},
			expectedCSRMatch:    renewedDefaultCSRMatch,
			expectedSecretMatch: secretNoCertMatch,
			expectedProgressing: pbool(true),
			expectFailedEvent:   true,
		},
		{
			name: "the csr was denied",
			csr: defaultCSRWithStatus(t,
				&certapiv1.CertificateSigningRequestStatus{
					Certificate: testCert,
					Conditions: []certapiv1.CertificateSigningRequestCondition{
						{
							Type:   certapiv1.CertificateDenied,
							Status: corev1.ConditionTrue,
						},
					},
				}),
			secretData:          map[string][]byte{"tls.key": testKey},
			expectedCSRMatch:    renewedDefaultCSRMatch,
			expectedSecretMatch: secretNoCertMatch,
			expectedProgressing: pbool(true),
			expectFailedEvent:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			operatorClient := v1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}, &operatorv1.OperatorStatus{}, nil)

			objects := []runtime.Object{}
			csrs := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tc.csr != nil {
				err := csrs.Add(tc.csr)
				require.NoError(t, err)
				objects = append(objects, tc.csr)
			}
			secrets := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tc.secretData != nil {
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: certSecretName, Namespace: "openshift-oauth-apiserver"},
					Data:       tc.secretData,
				}
				err := secrets.Add(secret)
				require.NoError(t, err)
				objects = append(objects, secret)
			}

			fakeClientset := fakeclients.NewSimpleClientset(objects...)
			controller := &webhookAuthenticatorCertRequester{
				operatorClient: operatorClient,

				csrLister: certv1listers.NewCertificateSigningRequestLister(csrs),
				csrClient: fakeClientset.CertificatesV1().CertificateSigningRequests(),

				secretLister: corev1listers.NewSecretLister(secrets),
				secretClient: fakeClientset.CoreV1().Secrets("openshift-oauth-apiserver"),
			}

			recorder := events.NewInMemoryRecorder("")
			syncCtx := factory.NewSyncContext("TestCertRequester", recorder)

			progressing, err := controller.sync(context.Background(), syncCtx)
			require.NoError(t, err)
			require.Equal(t, boolPToString(tc.expectedProgressing), boolPToString(progressing))

			csrGot, _ := controller.csrClient.Get(context.Background(), csrName, metav1.GetOptions{})

			secretGot, err := controller.secretClient.Get(context.Background(), certSecretName, metav1.GetOptions{})
			require.NoError(t, err)

			tc.expectedCSRMatch(t, csrGot)
			tc.expectedSecretMatch(t, secretGot)

			var foundFailedEvent bool
			for _, e := range recorder.Events() {
				if e.Reason == "CSRFailure" {
					foundFailedEvent = true
					break
				}
			}
			require.Equal(t, tc.expectFailedEvent, foundFailedEvent, "events %v", recorder.Events())

		})
	}
}

func boolPToString(b *bool) string {
	switch {
	case b == nil:
		return "<nil>"
	case *b == false:
		return "false"
	default:
		return "true"
	}
}

func pemDecodeCSR(t *testing.T, csrBytes []byte) *x509.CertificateRequest {
	csrPEM, rest := pem.Decode(csrBytes)
	if csrPEM == nil {
		t.Fatalf("failed to decode CSR PEM")
	}
	if len(rest) != 0 {
		t.Fatalf("there were more objects than just a CSR")
	}
	csr, err := x509.ParseCertificateRequest(csrPEM.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}

	return csr
}

func defaultCSRWithStatus(t *testing.T, csrStatus *certapiv1.CertificateSigningRequestStatus) *certapiv1.CertificateSigningRequest {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err, "failed to generate a private key: %v", err)

	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "system:serviceaccount:openshift-oauth-apiserver:openshift-authenticator"},
		},
		key,
	)
	require.NoError(t, err, "failed to create a CSR: %v", err)

	csrPEM, err := pemEncodeCSR(csrDER)
	require.NoError(t, err, "failed to PEM-encode the CSR: %v", err)

	return &certapiv1.CertificateSigningRequest{
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
		Status: *csrStatus,
	}
}

func testCertKeyPair(t *testing.T) ([]byte, []byte) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err, "failed to generate a private key: %v", err)

	keyPEM, err := pemEncodeRSAPrivate(key)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: bigIntOrDie(t),
		Subject:      pkix.Name{CommonName: "system:serviceaccount:openshift-oauth-apiserver:openshift-authenticator"},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err, "failed to create a certificate: %v", err)

	certBuffer := bytes.Buffer{}
	err = pem.Encode(&certBuffer,
		&pem.Block{Type: "CERTIFICATE", Bytes: cert},
	)
	require.NoError(t, err, "failed to convert DER cert into a PEM-formatted block: %w", err)

	return certBuffer.Bytes(), keyPEM
}

func bigIntOrDie(t *testing.T) *big.Int {
	rnum, err := rand.Int(rand.Reader, big.NewInt(100000))
	require.NoError(t, err)
	return rnum
}
