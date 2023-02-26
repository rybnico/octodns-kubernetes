## Kubernetes provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) source for Kubernetes.

Reads Kubernetes Ingress resource annotations and creates DNS records for them.

### Installation

#### Command line

```
pip install octodns-kubernetes
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==0.9.14
octodns-kubernetes==0.0.1
```

##### SHAs

```
# Start with the latest/specific versions and don't just copy what's here
-e git+https://git@github.com/octodns/octodns.git@9da19749e28f68407a1c246dfdf65663cdc1c422#egg=octodns
-e git+https://git@github.com/octodns/octodns-kubernetes.git@ec9661f8b335241ae4746eea467a8509205e6a30#egg=octodns_kubernetes
```

### Configuration

```yaml
providers:
  kubernetes:
    class: octodns_kubernetes.KubernetesSource
    hostnameAnnotations:
      - octodns-kubernetes.rybni.co/hostname # default
      - external-dns.alpha.kubernetes.io/hostname
    ttlAnnotations:
      - octodns-kubernetes.rybni.co/ttl # default
      - external-dns.alpha.kubernetes.io/ttl
    targetAnnotations:
      - octodns-kubernetes.rybni.co/target # default
      - external-dns.alpha.kubernetes.io/target
```

The kubeconfig is read from the file specified in the `KUBECONFIG` environment variable or from the default location. If it's not found, an in-cluster config is attempted.

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.
