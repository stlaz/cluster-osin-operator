package configobservercontroller

import (
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"k8s.io/client-go/tools/cache"
)

type ConfigObserverController struct {
	informers             []factory.Informer
	interestingNamespaces []string
	configObservers       []configobserver.ObserveConfigFunc

	configInformer             configinformers.SharedInformerFactory
	resourceSyncer             resourcesynccontroller.ResourceSyncer
	operatorClient             v1helpers.OperatorClient
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces
	eventRecorder              events.Recorder
}

func NewConfigObserver(
	operatorClient v1helpers.OperatorClient,
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	configInformer configinformers.SharedInformerFactory,
	resourceSyncer resourcesynccontroller.ResourceSyncer,
	eventRecorder events.Recorder,
) *ConfigObserverController {

	c := &ConfigObserverController{
		operatorClient:             operatorClient,
		kubeInformersForNamespaces: kubeInformersForNamespaces,
		configInformer:             configInformer,
		resourceSyncer:             resourceSyncer,
		eventRecorder:              eventRecorder,
	}

	c.interestingNamespaces = []string{
		"openshift-config",
		"openshift-config-managed",
	}

	c.informers = []factory.Informer{
		operatorClient.Informer(),
		configInformer.Config().V1().APIServers().Informer(),
		configInformer.Config().V1().Consoles().Informer(),
		configInformer.Config().V1().Infrastructures().Informer(),
		configInformer.Config().V1().OAuths().Informer(),
	}

	return c
}

func (c *ConfigObserverController) AddConfigObservers(cos []configobserver.ObserveConfigFunc) {
	c.configObservers = append(c.configObservers, cos...)
}

func (c *ConfigObserverController) AddNamespaceToWatchConfigMapsAndSecrets(ns string) {
	c.interestingNamespaces = append(c.interestingNamespaces, ns)
}

func (c *ConfigObserverController) ToController() factory.Controller {

	for _, ns := range c.interestingNamespaces {
		c.informers = append(c.informers,
			c.kubeInformersForNamespaces.InformersFor(ns).Core().V1().ConfigMaps().Informer(),
			c.kubeInformersForNamespaces.InformersFor(ns).Core().V1().Secrets().Informer(),
		)
	}

	preRunCacheSynced := []cache.InformerSynced{}
	for _, inf := range c.informers {
		preRunCacheSynced = append(preRunCacheSynced, inf.HasSynced)
	}

	return configobserver.NewConfigObserver(
		c.operatorClient,
		c.eventRecorder,
		Listers{
			ConfigMapLister: c.kubeInformersForNamespaces.ConfigMapLister(),
			SecretsLister:   c.kubeInformersForNamespaces.SecretLister(),

			APIServerLister_:     c.configInformer.Config().V1().APIServers().Lister(),
			ConsoleLister:        c.configInformer.Config().V1().Consoles().Lister(),
			InfrastructureLister: c.configInformer.Config().V1().Infrastructures().Lister(),
			OAuthLister:          c.configInformer.Config().V1().OAuths().Lister(),
			ResourceSync:         c.resourceSyncer,
			PreRunCachesSynced:   preRunCacheSynced,
		},
		c.informers,
		c.configObservers...,
	)
}
