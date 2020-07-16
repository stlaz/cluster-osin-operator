package oauthapi

import (
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/configobserver/apiserver"
)

const (
	OAuthAPIServerConfigPrefix = "oauthAPIServer"
)

func OauthAPIServerObservers() []configobserver.ObserveConfigFunc {
	oauthAPIServerObservers := []configobserver.ObserveConfigFunc{}
	for _, o := range []configobserver.ObserveConfigFunc{
		apiserver.ObserveAdditionalCORSAllowedOriginsToArguments,
		apiserver.ObserveTLSSecurityProfileToArguments,
	} {
		oauthAPIServerObservers = append(oauthAPIServerObservers, configobserver.WithPrefix(o, OAuthAPIServerConfigPrefix))
	}
	return oauthAPIServerObservers
}
