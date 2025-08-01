---
title: zarf init
description: Zarf CLI command reference for <code>zarf init</code>.
tableOfContents: false
---

<!-- Page generated by Zarf; DO NOT EDIT -->

## zarf init

Prepares a k8s cluster for the deployment of Zarf packages

### Synopsis

Injects an OCI registry as well as an optional git server into a Kubernetes cluster in the zarf namespace to support future application deployments.
If you do not have a cluster already configured, this command will give you the ability to install a cluster locally.

This command looks for a zarf-init package in the local directory that the command was executed from. If no package is found in the local directory and the Zarf CLI exists somewhere outside of the current directory, Zarf will failover and attempt to find a zarf-init package in the directory that the Zarf binary is located in.





```
zarf init [flags]
```

### Examples

```

# Initializing without any optional components:
$ zarf init

# Initializing w/ Zarfs internal git server:
$ zarf init --components=git-server

# Initializing w/ an internal registry but with a different nodeport:
$ zarf init --nodeport=30333

# Initializing w/ an external registry:
$ zarf init --registry-push-password={PASSWORD} --registry-push-username={USERNAME} --registry-url={URL}

# Initializing w/ an external git server:
$ zarf init --git-push-password={PASSWORD} --git-push-username={USERNAME} --git-url={URL}

# Initializing w/ an external artifact server:
$ zarf init --artifact-push-password={PASSWORD} --artifact-push-username={USERNAME} --artifact-url={URL}

# NOTE: Not specifying a pull username/password will use the push user for pulling as well.

```

### Options

```
      --adopt-existing-resources        Adopts any pre-existing K8s resources into the Helm charts managed by Zarf. ONLY use when you have existing deployments you want Zarf to takeover.
      --artifact-push-token string      [alpha] API Token for the push-user to access the artifact registry
      --artifact-push-username string   [alpha] Username to access to the artifact registry Zarf is configured to use. User must be able to upload package artifacts.
      --artifact-url string             [alpha] External artifact registry url to use for this Zarf cluster
      --components string               Specify which optional components to install.  E.g. --components=git-server
      --confirm                         Confirms package deployment without prompting. ONLY use with packages you trust. Skips prompts to review SBOM, configure variables, select optional components and review potential breaking changes.
      --git-pull-password string        Password for the pull-only user to access the git server
      --git-pull-username string        Username for pull-only access to the git server
      --git-push-password string        Password for the push-user to access the git server
      --git-push-username string        Username to access to the git server Zarf is configured to use. User must be able to create repositories via 'git push' (default "zarf-git-user")
      --git-url string                  External git server url to use for this Zarf cluster
  -h, --help                            help for init
  -k, --key string                      Path to public key file for validating signed packages
      --nodeport int                    Nodeport to access a registry internal to the k8s cluster. Between [30000-32767]
      --oci-concurrency int             Number of concurrent layer operations when pulling or pushing images or packages to/from OCI registries. (default 6)
      --registry-pull-password string   Password for the pull-only user to access the registry
      --registry-pull-username string   Username for pull-only access to the registry
      --registry-push-password string   Password for the push-user to connect to the registry
      --registry-push-username string   Username to access to the registry Zarf is configured to use (default "zarf-push")
      --registry-secret string          Registry secret value
      --registry-url string             External registry url address to use for this Zarf cluster
      --retries int                     Number of retries to perform for Zarf deploy operations like git/image pushes or Helm installs (default 3)
      --set stringToString              Specify deployment variables to set on the command line (KEY=value) (default [])
      --skip-signature-validation       Skip validating the signature of the Zarf package
      --storage-class string            Specify the storage class to use for the registry and git server.  E.g. --storage-class=standard
      --timeout duration                Timeout for health checks and Helm operations such as installs and rollbacks (default 15m0s)
```

### Options inherited from parent commands

```
  -a, --architecture string        Architecture for OCI images and Zarf packages
      --insecure-skip-tls-verify   Skip checking server's certificate for validity. This flag should only be used if you have a specific reason and accept the reduced security posture.
      --log-format string          Select a logging format. Defaults to 'console'. Valid options are: 'console', 'json', 'dev'. (default "console")
  -l, --log-level string           Log level when running Zarf. Valid options are: warn, info, debug, trace (default "info")
      --no-color                   Disable terminal color codes in logging and stdout prints.
      --plain-http                 Force the connections over HTTP instead of HTTPS. This flag should only be used if you have a specific reason and accept the reduced security posture.
      --tmpdir string              Specify the temporary directory to use for intermediate files
      --zarf-cache string          Specify the location of the Zarf cache directory (default "~/.zarf-cache")
```

### SEE ALSO

* [zarf](/commands/zarf/)	 - The Airgap Native Packager Manager for Kubernetes

