package aks

import (
	"context"
	"errors"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v5"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/rancher/aks-operator/pkg/aks/services/mock_services"
	"go.uber.org/mock/gomock"
)

const execKubeConfigYAML = `
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCnRlc3QKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
    server: https://test.com
  name: test
contexts:
- context:
    cluster: test
    user: test
  name: test
current-context: test
kind: Config
preferences: {}
users:
- name: test
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: kubelogin
      args:
      - get-token
      - --server-id
      - test-server-app-id
      - --client-id
      - test-client-app-id`

const authProviderKubeConfigYAML = `
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCnRlc3QKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
    server: https://test.com
  name: test
contexts:
- context:
    cluster: test
    user: test
  name: test
current-context: test
kind: Config
preferences: {}
users:
- name: test
  user:
    auth-provider:
      name: azure
      config:
        apiserver-id: test-server-app-id
        client-id: test-client-app-id`

const anonymousKubeConfigYAML = `
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCnRlc3QKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
    server: https://test.com
  name: test
contexts:
- context:
    cluster: test
    user: test
  name: test
current-context: test
kind: Config
preferences: {}
users:
- name: test
  user: {}`

type fakeTokenCredential struct {
	token  string
	scopes []string
	err    error
}

func (f *fakeTokenCredential) GetToken(_ context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.scopes = options.Scopes
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	return azcore.AccessToken{Token: f.token, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

var _ = Describe("GetClusterUserKubeConfig", func() {
	var (
		mockController    *gomock.Controller
		clusterClientMock *mock_services.MockManagedClustersClientInterface
	)

	BeforeEach(func() {
		mockController = gomock.NewController(GinkgoT())
		clusterClientMock = mock_services.NewMockManagedClustersClientInterface(mockController)
	})

	AfterEach(func() {
		mockController.Finish()
	})

	It("should return the first non empty kubeconfig", func() {
		clusterClientMock.EXPECT().ListClusterUserCredentials(ctx, "test-rg", "test-cluster", nil).
			Return(armcontainerservice.ManagedClustersClientListClusterUserCredentialsResponse{
				CredentialResults: armcontainerservice.CredentialResults{
					Kubeconfigs: []*armcontainerservice.CredentialResult{
						{Name: to.Ptr("empty")},
						{Name: to.Ptr("clusterUser"), Value: []byte(execKubeConfigYAML)},
					},
				},
			}, nil)

		kubeConfig, err := GetClusterUserKubeConfig(ctx, clusterClientMock, "test-rg", "test-cluster")
		Expect(err).ToNot(HaveOccurred())
		Expect(kubeConfig).To(Equal([]byte(execKubeConfigYAML)))
	})

	It("should return error if azure request fails", func() {
		clusterClientMock.EXPECT().ListClusterUserCredentials(ctx, "test-rg", "test-cluster", nil).
			Return(armcontainerservice.ManagedClustersClientListClusterUserCredentialsResponse{}, errors.New("failed to list credentials"))

		_, err := GetClusterUserKubeConfig(ctx, clusterClientMock, "test-rg", "test-cluster")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("failed to list credentials"))
	})

	It("should return error if no kubeconfig is returned", func() {
		clusterClientMock.EXPECT().ListClusterUserCredentials(ctx, "test-rg", "test-cluster", nil).
			Return(armcontainerservice.ManagedClustersClientListClusterUserCredentialsResponse{}, nil)

		_, err := GetClusterUserKubeConfig(ctx, clusterClientMock, "test-rg", "test-cluster")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("no user kubeconfig returned"))
	})
})

var _ = Describe("RESTConfigFromClusterUserKubeConfig", func() {
	It("should replace the credential plugin with a token", func() {
		credential := &fakeTokenCredential{token: "test-token"}

		restConfig, err := RESTConfigFromClusterUserKubeConfig(ctx, []byte(execKubeConfigYAML), credential)
		Expect(err).ToNot(HaveOccurred())
		Expect(restConfig.Host).To(Equal("https://test.com"))
		Expect(restConfig.CAData).ToNot(BeEmpty())
		Expect(restConfig.ExecProvider).To(BeNil())
		Expect(restConfig.AuthProvider).To(BeNil())
		Expect(restConfig.BearerToken).To(Equal("test-token"))
		Expect(credential.scopes).To(Equal([]string{"test-server-app-id/.default"}))
	})

	It("should replace the azure auth provider with a token", func() {
		credential := &fakeTokenCredential{token: "test-token"}

		restConfig, err := RESTConfigFromClusterUserKubeConfig(ctx, []byte(authProviderKubeConfigYAML), credential)
		Expect(err).ToNot(HaveOccurred())
		Expect(restConfig.ExecProvider).To(BeNil())
		Expect(restConfig.AuthProvider).To(BeNil())
		Expect(restConfig.BearerToken).To(Equal("test-token"))
		Expect(credential.scopes).To(Equal([]string{"test-server-app-id/.default"}))
	})

	It("should fall back to the well known AKS server application", func() {
		credential := &fakeTokenCredential{token: "test-token"}

		_, err := RESTConfigFromClusterUserKubeConfig(ctx, []byte(anonymousKubeConfigYAML), credential)
		Expect(err).ToNot(HaveOccurred())
		Expect(credential.scopes).To(Equal([]string{aksAADServerApplicationID + "/.default"}))
	})

	It("shouldn't request a token if no credential is given", func() {
		restConfig, err := RESTConfigFromClusterUserKubeConfig(ctx, []byte(execKubeConfigYAML), nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(restConfig.Host).To(Equal("https://test.com"))
		Expect(restConfig.CAData).ToNot(BeEmpty())
		Expect(restConfig.BearerToken).To(BeEmpty())
	})

	It("should return error if the kubeconfig is invalid", func() {
		_, err := RESTConfigFromClusterUserKubeConfig(ctx, []byte("invalid"), nil)
		Expect(err).To(HaveOccurred())
	})

	It("should return error if the token can't be requested", func() {
		credential := &fakeTokenCredential{err: errors.New("failed to get token")}

		_, err := RESTConfigFromClusterUserKubeConfig(ctx, []byte(execKubeConfigYAML), credential)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("failed to get token"))
	})
})
