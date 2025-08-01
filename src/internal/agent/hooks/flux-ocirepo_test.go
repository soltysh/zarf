// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

package hooks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	fluxmeta "github.com/fluxcd/pkg/apis/meta"
	flux "github.com/fluxcd/source-controller/api/v1"
	"github.com/stretchr/testify/require"
	"github.com/zarf-dev/zarf/src/config"
	"github.com/zarf-dev/zarf/src/internal/agent/http/admission"
	"github.com/zarf-dev/zarf/src/internal/agent/operations"
	"github.com/zarf-dev/zarf/src/pkg/state"
	"github.com/zarf-dev/zarf/src/pkg/transform"
	v1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"oras.land/oras-go/v2"
)

func createFluxOCIRepoAdmissionRequest(t *testing.T, op v1.Operation, fluxOCIRepo *flux.OCIRepository) *v1.AdmissionRequest {
	t.Helper()
	raw, err := json.Marshal(fluxOCIRepo)
	require.NoError(t, err)
	return &v1.AdmissionRequest{
		Operation: op,
		Object: runtime.RawExtension{
			Raw: raw,
		},
	}
}

func TestFluxOCIMutationWebhook(t *testing.T) {
	// t.Parallel()

	port, err := GetAvailableNodePort()
	require.NoError(t, err)

	tests := []admissionTest{
		{
			name: "should be mutated but not the tag",
			admissionReq: createFluxOCIRepoAdmissionRequest(t, v1.Create, &flux.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name: "mutate-this",
				},
				Spec: flux.OCIRepositorySpec{
					URL: "oci://ghcr.io/stefanprodan/charts/podinfo",
					Reference: &flux.OCIRepositoryRef{
						Tag: "6.9.0",
					},
				},
			}),
			patch: []operations.PatchOperation{
				operations.ReplacePatchOperation(
					"/spec/url",
					fmt.Sprintf("oci://127.0.0.1:%d/stefanprodan/charts/podinfo", port),
				),
				operations.AddPatchOperation(
					"/spec/secretRef",
					fluxmeta.LocalObjectReference{Name: config.ZarfImagePullSecretName},
				),
				operations.ReplacePatchOperation(
					"/spec/ref/tag",
					"6.9.0",
				),
				operations.ReplacePatchOperation(
					"/metadata/labels",
					map[string]string{
						"zarf-agent": "patched",
					},
				),
			},
			code: http.StatusOK,
		},
		{
			name: "should be mutated",
			admissionReq: createFluxOCIRepoAdmissionRequest(t, v1.Create, &flux.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name: "mutate-this",
				},
				Spec: flux.OCIRepositorySpec{
					URL: "oci://ghcr.io/stefanprodan/podinfo",
					Reference: &flux.OCIRepositoryRef{
						Tag: "6.9.0",
					},
				},
			}),
			patch: []operations.PatchOperation{
				operations.ReplacePatchOperation(
					"/spec/url",
					fmt.Sprintf("oci://127.0.0.1:%d/stefanprodan/podinfo", port),
				),
				operations.AddPatchOperation(
					"/spec/secretRef",
					fluxmeta.LocalObjectReference{Name: config.ZarfImagePullSecretName},
				),
				operations.ReplacePatchOperation(
					"/spec/ref/tag",
					"6.9.0-zarf-2985051089",
				),
				operations.ReplacePatchOperation(
					"/metadata/labels",
					map[string]string{
						"zarf-agent": "patched",
					},
				),
			},
			code: http.StatusOK,
		},
		{
			name: "bad oci url",
			admissionReq: createFluxOCIRepoAdmissionRequest(t, v1.Update, &flux.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name: "bad oci url",
				},
				Spec: flux.OCIRepositorySpec{
					URL: "bad://ghcr.io/$",
				},
			}),
			errContains: "unable to transform the OCIRepo URL",
			code:        http.StatusInternalServerError,
		},
		{
			name: "should be mutated with no internal service registry",
			admissionReq: createFluxOCIRepoAdmissionRequest(t, v1.Update, &flux.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name: "mutate-this",
				},
				Spec: flux.OCIRepositorySpec{
					URL: "oci://ghcr.io/stefanprodan/manifests/podinfo",
					Reference: &flux.OCIRepositoryRef{
						Tag: "6.4.0",
					},
				},
			}),
			patch: []operations.PatchOperation{
				operations.ReplacePatchOperation(
					"/spec/url",
					fmt.Sprintf("oci://127.0.0.1:%d/stefanprodan/manifests/podinfo", port),
				),
				operations.AddPatchOperation(
					"/spec/secretRef",
					fluxmeta.LocalObjectReference{Name: config.ZarfImagePullSecretName},
				),
				operations.ReplacePatchOperation(
					"/spec/ref/tag",
					"6.4.0-zarf-2823281104",
				),
				operations.ReplacePatchOperation(
					"/metadata/labels",
					map[string]string{
						"zarf-agent": "patched",
					},
				),
			},
			code: http.StatusOK,
		},
		{
			name: "test semver tag",
			admissionReq: createFluxOCIRepoAdmissionRequest(t, v1.Update, &flux.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name: "mutate-this",
				},
				Spec: flux.OCIRepositorySpec{
					URL: "oci://ghcr.io/stefanprodan/manifests/podinfo",
					Reference: &flux.OCIRepositoryRef{
						SemVer: ">= 6.4.0",
					},
				},
			}),
			patch: []operations.PatchOperation{
				operations.ReplacePatchOperation(
					"/spec/url",
					fmt.Sprintf("oci://127.0.0.1:%d/stefanprodan/manifests/podinfo", port),
				),
				operations.AddPatchOperation(
					"/spec/secretRef",
					fluxmeta.LocalObjectReference{Name: config.ZarfImagePullSecretName},
				),
				operations.ReplacePatchOperation(
					"/metadata/labels",
					map[string]string{
						"zarf-agent": "patched",
					},
				),
			},
			code: http.StatusOK,
		},
		{
			name: "should be mutated with internal service registry",
			admissionReq: createFluxOCIRepoAdmissionRequest(t, v1.Create, &flux.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name: "mutate-this",
				},
				Spec: flux.OCIRepositorySpec{
					URL: "oci://ghcr.io/stefanprodan/charts",
					Reference: &flux.OCIRepositoryRef{
						Digest: "sha256:6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
					},
				},
			}),
			patch: []operations.PatchOperation{
				operations.ReplacePatchOperation(
					"/spec/url",
					"oci://10.11.12.13:5000/stefanprodan/charts",
				),
				operations.AddPatchOperation(
					"/spec/secretRef",
					fluxmeta.LocalObjectReference{Name: config.ZarfImagePullSecretName},
				),
				operations.ReplacePatchOperation(
					"/metadata/labels",
					map[string]string{
						"zarf-agent": "patched",
					},
				),
			},
			svc: &corev1.Service{
				TypeMeta: metav1.TypeMeta{
					APIVersion: corev1.SchemeGroupVersion.String(),
					Kind:       "Service",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "zarf-docker-registry",
					Namespace: "zarf",
				},
				Spec: corev1.ServiceSpec{
					Type: corev1.ServiceTypeNodePort,
					Ports: []corev1.ServicePort{
						{
							NodePort: int32(port),
							Port:     5000,
						},
					},
					ClusterIP: "10.11.12.13",
				},
			},
			code: http.StatusOK,
		},
		{
			name: "should not mutate URL if it has the same hostname as Zarf s",
			admissionReq: createFluxOCIRepoAdmissionRequest(t, v1.Update, &flux.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name: "mutate-this",
				},
				Spec: flux.OCIRepositorySpec{
					URL: fmt.Sprintf("oci://127.0.0.1:%d/stefanprodan/manifests/podinfo", port),
					Reference: &flux.OCIRepositoryRef{
						Tag: "6.4.0-zarf-2823281104",
					},
				},
			}),
			patch: []operations.PatchOperation{
				operations.ReplacePatchOperation(
					"/spec/url",
					fmt.Sprintf("oci://127.0.0.1:%d/stefanprodan/manifests/podinfo", port),
				),
				operations.AddPatchOperation(
					"/spec/secretRef",
					fluxmeta.LocalObjectReference{Name: config.ZarfImagePullSecretName},
				),
				operations.ReplacePatchOperation(
					"/spec/ref/tag",
					"6.4.0-zarf-2823281104",
				),
				operations.ReplacePatchOperation(
					"/metadata/labels",
					map[string]string{
						"zarf-agent": "patched",
					},
				),
			},
			code: http.StatusOK,
		},
		{
			name: "should not mutate URL if it has the same hostname as Zarfs internal repo",
			admissionReq: createFluxOCIRepoAdmissionRequest(t, v1.Update, &flux.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name: "mutate-this",
				},
				Spec: flux.OCIRepositorySpec{
					URL: "oci://10.11.12.13:5000/stefanprodan/charts",
					Reference: &flux.OCIRepositoryRef{
						Digest: "sha256:6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
					},
				},
			}),
			patch: []operations.PatchOperation{
				operations.ReplacePatchOperation(
					"/spec/url",
					"oci://10.11.12.13:5000/stefanprodan/charts",
				),
				operations.AddPatchOperation(
					"/spec/secretRef",
					fluxmeta.LocalObjectReference{Name: config.ZarfImagePullSecretName},
				),
				operations.ReplacePatchOperation(
					"/metadata/labels",
					map[string]string{
						"zarf-agent": "patched",
					},
				),
			},
			svc: &corev1.Service{
				TypeMeta: metav1.TypeMeta{
					APIVersion: corev1.SchemeGroupVersion.String(),
					Kind:       "Service",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "zarf-docker-registry",
					Namespace: "zarf",
				},
				Spec: corev1.ServiceSpec{
					Type: corev1.ServiceTypeNodePort,
					Ports: []corev1.ServicePort{
						{
							NodePort: int32(port),
							Port:     5000,
						},
					},
					ClusterIP: "10.11.12.13",
				},
			},
			code: http.StatusOK,
		},
	}

	var artifacts = []transform.Image{
		{
			Host: "ghcr.io",
			Path: "stefanprodan/charts/podinfo",
			Tag:  "6.9.0",
		},
		{
			Host: "ghcr.io",
			Path: "stefanprodan/manifests/podinfo",
			Tag:  "6.9.0",
		},
	}

	ctx := context.Background()
	_, err = setupRegistry(ctx, t, port, artifacts, oras.DefaultCopyOptions)
	require.NoError(t, err)

	s := &state.State{RegistryInfo: state.RegistryInfo{Address: fmt.Sprintf("127.0.0.1:%d", port)}}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// t.Parallel()
			c := createTestClientWithZarfState(ctx, t, s)
			handler := admission.NewHandler().Serve(ctx, NewOCIRepositoryMutationHook(ctx, c))
			if tt.svc != nil {
				_, err := c.Clientset.CoreV1().Services("zarf").Create(ctx, tt.svc, metav1.CreateOptions{})
				require.NoError(t, err)
			}
			rr := sendAdmissionRequest(t, tt.admissionReq, handler)
			verifyAdmission(t, rr, tt)
		})
	}
}
