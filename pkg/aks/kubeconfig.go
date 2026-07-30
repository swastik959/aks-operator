package aks

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/rancher/aks-operator/pkg/aks/services"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	// aksAADServerApplicationID is the well known application ID of the AKS Microsoft Entra ID server
	// application. The API server of a cluster with Microsoft Entra ID integration accepts tokens issued for
	// this application. It is only used as a fallback, the application ID advertised by the kubeconfig
	// returned by AKS takes precedence.
	aksAADServerApplicationID = "6dae42f8-4368-4678-94ff-3960e28e3630"

	// serverIDExecArg is the argument the kubelogin credential plugin is called with to identify the
	// Microsoft Entra ID server application of the cluster.
	serverIDExecArg = "--server-id"

	// apiServerIDAuthProviderKey is the key holding the Microsoft Entra ID server application in the
	// configuration of the azure auth provider.
	apiServerIDAuthProviderKey = "apiserver-id"
)

// GetClusterUserKubeConfig returns the cluster user kubeconfig of an AKS cluster. Unlike the cluster admin
// kubeconfig, it is available on clusters that have local accounts disabled.
func GetClusterUserKubeConfig(ctx context.Context, clusterClient services.ManagedClustersClientInterface, resourceGroupName string, resourceName string) ([]byte, error) {
	credentials, err := clusterClient.ListClusterUserCredentials(ctx, resourceGroupName, resourceName, nil)
	if err != nil {
		return nil, err
	}

	for _, kubeConfig := range credentials.Kubeconfigs {
		if kubeConfig != nil && len(kubeConfig.Value) != 0 {
			return kubeConfig.Value, nil
		}
	}

	return nil, fmt.Errorf("no user kubeconfig returned for cluster [%s]", resourceName)
}

// RESTConfigFromClusterUserKubeConfig builds a rest config from the cluster user kubeconfig of an AKS
// cluster. AKS returns a kubeconfig that authenticates through the kubelogin credential plugin, or through
// the azure auth provider that client-go no longer supports. Neither of them is available to the operator,
// so the credential configuration is replaced with a token requested for the Microsoft Entra ID server
// application of the cluster. When credential is nil no token is requested and the returned config only
// holds the connection details of the cluster.
func RESTConfigFromClusterUserKubeConfig(ctx context.Context, kubeConfig []byte, credential azcore.TokenCredential) (*rest.Config, error) {
	rawConfig, err := clientcmd.Load(kubeConfig)
	if err != nil {
		return nil, err
	}

	serverApplicationID := aksAADServerApplicationID
	for _, authInfo := range rawConfig.AuthInfos {
		if id := serverApplicationIDFromAuthInfo(authInfo); id != "" {
			serverApplicationID = id
		}
		authInfo.AuthProvider = nil
		authInfo.Exec = nil
	}

	restConfig, err := clientcmd.NewDefaultClientConfig(*rawConfig, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, err
	}

	if credential == nil {
		return restConfig, nil
	}

	token, err := credential.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{serverApplicationID + "/.default"},
	})
	if err != nil {
		return nil, fmt.Errorf("error getting token for application [%s]: %w", serverApplicationID, err)
	}
	restConfig.BearerToken = token.Token

	return restConfig, nil
}

// serverApplicationIDFromAuthInfo returns the Microsoft Entra ID server application the given user is
// expected to authenticate against, or an empty string when the user doesn't advertise one.
func serverApplicationIDFromAuthInfo(authInfo *clientcmdapi.AuthInfo) string {
	if authInfo == nil {
		return ""
	}

	if authInfo.AuthProvider != nil {
		if id := authInfo.AuthProvider.Config[apiServerIDAuthProviderKey]; id != "" {
			return id
		}
	}

	if authInfo.Exec != nil {
		for i, arg := range authInfo.Exec.Args {
			if arg == serverIDExecArg && i+1 < len(authInfo.Exec.Args) {
				return authInfo.Exec.Args[i+1]
			}
		}
	}

	return ""
}
