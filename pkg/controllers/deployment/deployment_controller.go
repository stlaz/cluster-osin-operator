package deployment

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	appsv1client "k8s.io/client-go/kubernetes/typed/apps/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	oauthv1 "github.com/openshift/api/oauth/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	oauthv1client "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	operatorv1client "github.com/openshift/client-go/operator/clientset/versioned/typed/operator/v1"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions"
	routev1lister "github.com/openshift/client-go/route/listers/route/v1"
	bootstrap "github.com/openshift/library-go/pkg/authentication/bootstrapauthenticator"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/oauth/oauthdiscovery"
	"github.com/openshift/library-go/pkg/operator/apiserver/controller/workload"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"github.com/openshift/library-go/pkg/route/routeapihelpers"
)

var _ workload.Delegate = &oauthServerDeploymentSyncer{}

func NewOAuthServerWorkloadController(
	kubeClient kubernetes.Interface,
	oauthClientClient oauthv1client.OAuthClientInterface,
	operatorClient v1helpers.OperatorClient,
	openshiftClusterConfigClient configv1client.ClusterOperatorInterface,

	routeInformer routeinformer.SharedInformerFactory,
	configInformers configinformer.SharedInformerFactory,
	authOperatorGetter operatorv1client.AuthenticationsGetter,
	bootstrapUserDataGetter bootstrap.BootstrapUserDataGetter,

	eventsRecorder events.Recorder,
	versionRecorder status.VersionGetter,

	kubeInformersForTargetNamespace informers.SharedInformerFactory,
) factory.Controller {
	targetNS := "openshift-authentication"

	oauthDeploymentSyncer := &oauthServerDeploymentSyncer{
		operatorClient:          operatorClient,
		oauthClientClient:       oauthClientClient,
		deployments:             kubeClient.AppsV1(),
		auth:                    authOperatorGetter,
		configMapLister:         kubeInformersForTargetNamespace.Core().V1().ConfigMaps().Lister(),
		secretLister:            kubeInformersForTargetNamespace.Core().V1().Secrets().Lister(),
		routeLister:             routeInformer.Route().V1().Routes().Lister(),
		podsLister:              kubeInformersForTargetNamespace.Core().V1().Pods().Lister(),
		ingressLister:           configInformers.Config().V1().Ingresses().Lister(),
		proxyLister:             configInformers.Config().V1().Proxies().Lister(),
		bootstrapUserDataGetter: bootstrapUserDataGetter,
	}

	if userExists, err := oauthDeploymentSyncer.bootstrapUserDataGetter.IsEnabled(); err != nil {
		klog.Warningf("Unable to determine the state of bootstrap user: %v", err)
		oauthDeploymentSyncer.bootstrapUserChangeRollOut = true
	} else {
		oauthDeploymentSyncer.bootstrapUserChangeRollOut = userExists
	}

	return workload.NewController(
		"OAuthServer",
		"cluster-authentication-operator",
		targetNS,
		os.Getenv("OPERAND_OAUTH_SERVER_IMAGE_VERSION"),
		"",
		"OAuthServer",
		operatorClient,
		kubeClient,
		kubeInformersForTargetNamespace.Core().V1().Pods().Lister(),
		[]factory.Informer{
			configInformers.Config().V1().Ingresses().Informer(),
			configInformers.Config().V1().Proxies().Informer(),
		},
		[]factory.Informer{
			kubeInformersForTargetNamespace.Apps().V1().Deployments().Informer(),
			kubeInformersForTargetNamespace.Core().V1().ConfigMaps().Informer(),
			kubeInformersForTargetNamespace.Core().V1().Secrets().Informer(),
			kubeInformersForTargetNamespace.Core().V1().Pods().Informer(),
			kubeInformersForTargetNamespace.Core().V1().Namespaces().Informer(),
			routeInformer.Route().V1().Routes().Informer(),
		},
		oauthDeploymentSyncer,
		openshiftClusterConfigClient,
		eventsRecorder,
		versionRecorder,
	)
}

type oauthServerDeploymentSyncer struct {
	operatorClient v1helpers.OperatorClient

	deployments       appsv1client.DeploymentsGetter
	oauthClientClient oauthv1client.OAuthClientInterface
	auth              operatorv1client.AuthenticationsGetter

	configMapLister corev1listers.ConfigMapLister
	secretLister    corev1listers.SecretLister
	podsLister      corev1listers.PodLister
	routeLister     routev1lister.RouteLister
	ingressLister   configv1listers.IngressLister
	proxyLister     configv1listers.ProxyLister

	bootstrapUserDataGetter    bootstrap.BootstrapUserDataGetter
	bootstrapUserChangeRollOut bool
}

func NewOAuthServerDeploymentSyncer(
	kubeInformersForTargetNamespace informers.SharedInformerFactory,
	routeInformer routeinformer.SharedInformerFactory,
	configInformers configinformer.SharedInformerFactory,
	operatorClient v1helpers.OperatorClient,
	authOperatorGetter operatorv1client.AuthenticationsGetter,
	oauthClientClient oauthv1client.OAuthClientInterface,
	deploymentsGetter appsv1client.DeploymentsGetter,
	bootstrapUserDataGetter bootstrap.BootstrapUserDataGetter,
	recorder events.Recorder,
) *oauthServerDeploymentSyncer {
	c := &oauthServerDeploymentSyncer{
		operatorClient:          operatorClient,
		oauthClientClient:       oauthClientClient,
		deployments:             deploymentsGetter,
		auth:                    authOperatorGetter,
		configMapLister:         kubeInformersForTargetNamespace.Core().V1().ConfigMaps().Lister(),
		secretLister:            kubeInformersForTargetNamespace.Core().V1().Secrets().Lister(),
		routeLister:             routeInformer.Route().V1().Routes().Lister(),
		podsLister:              kubeInformersForTargetNamespace.Core().V1().Pods().Lister(),
		ingressLister:           configInformers.Config().V1().Ingresses().Lister(),
		proxyLister:             configInformers.Config().V1().Proxies().Lister(),
		bootstrapUserDataGetter: bootstrapUserDataGetter,
	}

	if userExists, err := c.bootstrapUserDataGetter.IsEnabled(); err != nil {
		klog.Warningf("Unable to determine the state of bootstrap user: %v", err)
		c.bootstrapUserChangeRollOut = true
	} else {
		c.bootstrapUserChangeRollOut = userExists
	}

	return c
}

func (c *oauthServerDeploymentSyncer) PreconditionFulfilled() (bool, error) {
	return true, nil
}

func (c *oauthServerDeploymentSyncer) Sync(ctx context.Context, syncContext factory.SyncContext) (*appsv1.Deployment, bool, []error) {
	errs := []error{}

	operatorConfig, err := c.auth.Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return nil, false, append(errs, err)
	}

	ingress, err := c.getIngressConfig()
	if err != nil {
		return nil, false, append(errs, err)
	}

	routeHost, err := c.getCanonicalRouteHost(ingress.Spec.Domain)
	if err != nil {
		return nil, false, append(errs, err)
	}

	proxyConfig, err := c.getProxyConfig()
	if err != nil {
		return nil, false, append(errs, err)
	}

	if err := c.ensureBootstrappedOAuthClients(ctx, "https://"+routeHost); err != nil {
		return nil, false, append(errs, err)
	}

	// resourceVersions serves to store versions of config resources so that we
	// can redeploy our payload should either change. We only omit the operator
	// config version, it would both cause redeploy loops (status updates cause
	// version change) and the relevant changes (logLevel, unsupportedConfigOverrides)
	// will cause a redeploy anyway
	// TODO move this hash from deployment meta to operatorConfig.status.generations.[...].hash
	resourceVersions := []string{}

	if len(proxyConfig.Name) > 0 {
		resourceVersions = append(resourceVersions, "proxy:"+proxyConfig.Name+":"+proxyConfig.ResourceVersion)
	}

	configResourceVersions, err := c.getConfigResourceVersions()
	if err != nil {
		return nil, false, append(errs, err)
	}

	resourceVersions = append(resourceVersions, configResourceVersions...)

	// Determine whether the bootstrap user has been deleted so that
	// detail can be used in computing the deployment.
	if c.bootstrapUserChangeRollOut {
		if userExists, err := c.bootstrapUserDataGetter.IsEnabled(); err != nil {
			klog.Warningf("Unable to determine the state of bootstrap user: %v", err)
		} else {
			c.bootstrapUserChangeRollOut = userExists
		}
	}

	// deployment, have RV of all resources
	expectedDeployment, err := getOAuthServerDeployment(operatorConfig, proxyConfig, c.bootstrapUserChangeRollOut, resourceVersions...)
	if err != nil {
		return nil, false, append(errs, err)
	}

	deployment, _, err := resourceapply.ApplyDeployment(c.deployments,
		syncContext.Recorder(),
		expectedDeployment,
		resourcemerge.ExpectedDeploymentGeneration(expectedDeployment, operatorConfig.Status.Generations),
	)
	if err != nil {
		return nil, false, append(errs, fmt.Errorf("applying deployment of the integrated OAuth server failed: %w", err))
	}

	return deployment, true, errs
}

func (c *oauthServerDeploymentSyncer) getCanonicalRouteHost(ingressConfigDomain string) (string, error) {
	route, err := c.routeLister.Routes("openshift-authentication").Get("oauth-openshift")
	if err != nil {
		return "", err
	}

	expectedHost := "oauth-openshift." + ingressConfigDomain
	routeHost, _, err := routeapihelpers.IngressURI(route, expectedHost)
	if err != nil {
		return "", err
	}
	return routeHost.Host, nil
}

func (c *oauthServerDeploymentSyncer) getProxyConfig() (*configv1.Proxy, error) {
	proxyConfig, err := c.proxyLister.Get("cluster")
	if err != nil {
		if !errors.IsNotFound(err) {
			klog.V(4).Infof("No proxy configuration found, defaulting to empty")
			return &configv1.Proxy{}, nil
		}
		return nil, fmt.Errorf("unable to get cluster proxy configuration: %v", err)
	}
	return proxyConfig, nil
}

func (c *oauthServerDeploymentSyncer) getConfigResourceVersions() ([]string, error) {
	var configRVs []string

	configMaps, err := c.configMapLister.ConfigMaps("openshift-authentication").List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("unable to list configmaps in %q namespace: %v", "openshift-authentication", err)
	}
	for _, cm := range configMaps {
		if strings.HasPrefix(cm.Name, "v4-0-config-") {
			// prefix the RV to make it clear where it came from since each resource can be from different etcd
			configRVs = append(configRVs, "configmaps:"+cm.Name+":"+cm.ResourceVersion)
		}
	}

	secrets, err := c.secretLister.Secrets("openshift-authentication").List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("unable to list secrets in %q namespace: %v", "openshift-authentication", err)
	}
	for _, secret := range secrets {
		if strings.HasPrefix(secret.Name, "v4-0-config-") {
			// prefix the RV to make it clear where it came from since each resource can be from different etcd
			configRVs = append(configRVs, "secrets:"+secret.Name+":"+secret.ResourceVersion)
		}
	}

	return configRVs, nil
}

func randomBits(bits int) []byte {
	size := bits / 8
	if bits%8 != 0 {
		size++
	}
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err) // rand should never fail
	}
	return b
}

func (c *oauthServerDeploymentSyncer) ensureBootstrappedOAuthClients(ctx context.Context, masterPublicURL string) error {
	browserClient := oauthv1.OAuthClient{
		ObjectMeta:            metav1.ObjectMeta{Name: "openshift-browser-client"},
		Secret:                base64.RawURLEncoding.EncodeToString(randomBits(256)),
		RespondWithChallenges: false,
		RedirectURIs:          []string{oauthdiscovery.OpenShiftOAuthTokenDisplayURL(masterPublicURL)},
		GrantMethod:           oauthv1.GrantHandlerAuto,
	}
	if err := ensureOAuthClient(ctx, c.oauthClientClient, browserClient); err != nil {
		return fmt.Errorf("unable to get %q bootstrapped OAuth client: %v", browserClient.Name, err)
	}

	cliClient := oauthv1.OAuthClient{
		ObjectMeta:            metav1.ObjectMeta{Name: "openshift-challenging-client"},
		Secret:                "",
		RespondWithChallenges: true,
		RedirectURIs:          []string{oauthdiscovery.OpenShiftOAuthTokenImplicitURL(masterPublicURL)},
		GrantMethod:           oauthv1.GrantHandlerAuto,
	}
	if err := ensureOAuthClient(ctx, c.oauthClientClient, cliClient); err != nil {
		return fmt.Errorf("unable to get %q bootstrapped CLI OAuth client: %v", browserClient.Name, err)
	}

	return nil
}

// updateOperatorDeploymentInfo updates the operator's Status .ReadyReplicas, .Generation and the
// .Generetions field with data about the oauth-server deployment
func (c *oauthServerDeploymentSyncer) updateOperatorDeploymentInfo(
	ctx context.Context,
	syncContext factory.SyncContext,
	operatorConfig *operatorv1.Authentication,
	deployment *appsv1.Deployment,
) error {
	operatorStatusOutdated := operatorConfig.Status.ObservedGeneration != operatorConfig.Generation ||
		operatorConfig.Status.ReadyReplicas != deployment.Status.UpdatedReplicas ||
		resourcemerge.ExpectedDeploymentGeneration(deployment, operatorConfig.Status.Generations) != deployment.Generation

	if operatorStatusOutdated {
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			operatorConfig, err := c.auth.Authentications().Get(ctx, "cluster", metav1.GetOptions{})
			if err != nil {
				return err
			}

			// make sure we record the changes to the deployment
			// if this fail, lets resync, this should not fail
			resourcemerge.SetDeploymentGeneration(&operatorConfig.Status.Generations, deployment)
			operatorConfig.Status.ObservedGeneration = operatorConfig.Generation
			operatorConfig.Status.ReadyReplicas = deployment.Status.UpdatedReplicas

			_, err = c.auth.Authentications().UpdateStatus(ctx, operatorConfig, metav1.UpdateOptions{})
			return err
		}); err != nil {
			syncContext.Recorder().Warningf("AuthenticationUpdateStatusFailed", "Failed to update authentication operator status: %v", err)
			return err
		}
	}
	return nil
}

func (c *oauthServerDeploymentSyncer) getIngressConfig() (*configv1.Ingress, error) {
	ingress, err := c.ingressLister.Get("cluster")
	if err != nil {
		return nil, fmt.Errorf("unable to get cluster ingress config: %v", err)
	}
	if len(ingress.Spec.Domain) == 0 {
		return nil, fmt.Errorf("the ingress config domain cannot be empty")
	}
	return ingress, nil
}
