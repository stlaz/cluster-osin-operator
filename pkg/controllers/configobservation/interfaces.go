package configobservation

import (
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation/console"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation/infrastructure"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation/oauth"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation/routersecret"
	"github.com/openshift/library-go/pkg/operator/configobserver/apiserver"

	"github.com/openshift/library-go/pkg/operator/configobserver"
)

const (
	OAuthServerConfigPrefix    = "oauthServer"
)

func OauthServerObservers() []configobserver.ObserveConfigFunc {
	oauthServerObservers := []configobserver.ObserveConfigFunc{}
	for _, o := range []configobserver.ObserveConfigFunc{
		apiserver.ObserveAdditionalCORSAllowedOrigins,
		apiserver.ObserveTLSSecurityProfile,
		console.ObserveConsoleURL,
		infrastructure.ObserveAPIServerURL,
		oauth.ObserveIdentityProviders,
		oauth.ObserveTemplates,
		oauth.ObserveTokenConfig,
		routersecret.ObserveRouterSecret,
	} {
		oauthServerObservers = append(oauthServerObservers,
			configobserver.WithPrefix(o, OAuthServerConfigPrefix))
	}
	return oauthServerObservers
}
