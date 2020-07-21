package configobservation

import (
	"k8s.io/client-go/tools/cache"

	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/configobserver/apiserver"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	OAuthAPIServerConfigPrefix = "oauthAPIServer"
)

func NewConfigObserverController(
	operatorClient v1helpers.OperatorClient,
	configInformer configinformers.SharedInformerFactory,
	resourceSyncer resourcesynccontroller.ResourceSyncer,
	eventRecorder events.Recorder,
) factory.Controller {

	preRunCacheSynced := []cache.InformerSynced{
		operatorClient.Informer().HasSynced,
		configInformer.Config().V1().APIServers().Informer().HasSynced,
	}

	informers := []factory.Informer{
		operatorClient.Informer(),
		configInformer.Config().V1().APIServers().Informer(),
	}

	observers := []configobserver.ObserveConfigFunc{}
	for _, o := range []configobserver.ObserveConfigFunc{
		apiserver.ObserveAdditionalCORSAllowedOriginsToArguments,
		apiserver.ObserveTLSSecurityProfileToArguments,
		// TODO: libgoetcd.ObserveStorageURLsToArguments,

	} {
		observers = append(observers,
			configobserver.WithPrefix(o, OAuthAPIServerConfigPrefix))
	}

	return configobserver.NewNestedConfigObserver(
		operatorClient,
		eventRecorder,
		Listers{
			APIServerLister_:   configInformer.Config().V1().APIServers().Lister(),
			ResourceSync:       resourceSyncer,
			PreRunCachesSynced: preRunCacheSynced,
		},
		informers,
		[]string{OAuthAPIServerConfigPrefix},
		observers...,
	)
}
