package webhookcerts

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	certapiv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	certv1informers "k8s.io/client-go/informers/certificates/v1"
	certv1client "k8s.io/client-go/kubernetes/typed/certificates/v1"
	certv1listers "k8s.io/client-go/listers/certificates/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

type csrApproverController struct {
	csrClient certv1client.CertificateSigningRequestInterface
	csrLister certv1listers.CertificateSigningRequestLister
}

// saGroupSet is the set of groups for the SA expected to have created the CSR
var saGroupSet = sets.NewString(
	"system:serviceaccounts",
	"system:serviceaccounts:openshift-authentication-operator",
	"system:authenticated",
)

// NewCSRApproverController returns a controller that is observing the CSR API
// for a CSR named "system:openshift:openshift-authenticator".
// If such a CSR exists, it checks that it was submitted by the system:serviceaccount:openshift-authentication-operator:authentication-operator
// SA and if so and it hasn't yet been approved, it auto-approves it
func NewCSRApproverController(
	operatorClient v1helpers.OperatorClient,
	csrClient certv1client.CertificateSigningRequestInterface,
	csrInformers certv1informers.CertificateSigningRequestInformer,
	eventsRecorder events.Recorder,
) factory.Controller {
	c := &csrApproverController{
		csrClient: csrClient,
		csrLister: csrInformers.Lister(),
	}

	return factory.New().
		WithSync(c.sync).
		WithSyncDegradedOnError(operatorClient).
		WithFilteredEventsInformers(nameFilter(csrName), csrInformers.Informer()).
		ToController("WebhookAuthenticatorCertApprover", eventsRecorder.WithComponentSuffix("webhook-authenticator-cert-approver"))
}

func (c *csrApproverController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	csr, err := c.csrLister.Get(csrName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	if csr.Spec.Username != "system:serviceaccount:openshift-authentication-operator:authentication-operator" {
		return fmt.Errorf("CSR %q was created by an unexpected user: %q", csrName, csr.Spec.Username)
	}

	if csrGroups := sets.NewString(csr.Spec.Groups...); !csrGroups.IsSuperset(saGroupSet) {
		return fmt.Errorf("CSR %q was created by a user with unexpected groups: %v", csrName, csrGroups.List())
	}

	if approved, denied := getCertApprovalCondition(&csr.Status); approved || denied {
		return nil
	}

	csrCopy := csr.DeepCopy()
	csrPEM, _ := pem.Decode(csrCopy.Spec.Request)
	if csrPEM == nil {
		return c.denyCSR(ctx, csrCopy, "NoCSRFound", "failed to PEM-parse the CSR block in .spec.request: no CSRs were found")
	}

	csrObj, err := x509.ParseCertificateRequest(csrPEM.Bytes)
	if err != nil {
		return c.denyCSR(ctx, csrCopy, "CSRParsingFailed", fmt.Sprintf("failed to parse the CSR bytes: %v", err))
	}

	if expectedSubject := "CN=system:serviceaccount:openshift-oauth-apiserver:openshift-authenticator"; csrObj.Subject.String() != expectedSubject {
		return c.denyCSR(ctx, csrCopy, "UnauthorizedCSRSubject", fmt.Sprintf("expected the CSR's subject to be %q, but it is %q", expectedSubject, csrObj.Subject.String()))
	}

	csrCopy.Status.Conditions = append(csrCopy.Status.Conditions,
		certapiv1.CertificateSigningRequestCondition{
			Type:    certapiv1.CertificateApproved,
			Status:  corev1.ConditionTrue,
			Reason:  "AutoApproved",
			Message: "Auto approving certificate for openshift-authenticator",
		},
	)

	_, err = c.csrClient.UpdateApproval(ctx, csrName, csrCopy, v1.UpdateOptions{})
	return err
}

func (c *csrApproverController) denyCSR(ctx context.Context, csrCopy *certapiv1.CertificateSigningRequest, reason, message string) error {
	csrCopy.Status.Conditions = append(csrCopy.Status.Conditions,
		certapiv1.CertificateSigningRequestCondition{
			Type:    certapiv1.CertificateDenied,
			Status:  corev1.ConditionTrue,
			Reason:  reason,
			Message: message,
		},
	)

	_, err := c.csrClient.UpdateApproval(ctx, csrName, csrCopy, v1.UpdateOptions{})
	return err
}

func getCertApprovalCondition(status *certapiv1.CertificateSigningRequestStatus) (approved bool, denied bool) {
	for _, c := range status.Conditions {
		if c.Type == certapiv1.CertificateApproved {
			approved = true
		}
		if c.Type == certapiv1.CertificateDenied {
			denied = true
		}
	}
	return
}
