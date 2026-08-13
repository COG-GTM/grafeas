# Running Grafeas Server

## Pre-requisites

* [Docker](https://www.docker.com/get-started), if planning to use Grafeas
  Docker image or build one
* [openssl](https://www.openssl.org/), if planning to use certificates

### Checkout your fork

The Go tools require that you clone the repository to the `src/github.com/grafeas/kritis` directory
in your [`GOPATH`](https://github.com/golang/go/wiki/SettingGOPATH).

To check out this repository:

1. Create your own [fork of this
  repo](https://help.github.com/articles/fork-a-repo/)
2. Clone it to your machine:

  ```bash
  GOPATH=$(go env GOPATH)
  mkdir -p ${GOPATH}/src/github.com/grafeas
  cd ${GOPATH}/src/github.com/grafeas
  git clone git@github.com:${YOUR_GITHUB_USERNAME}/grafeas.git
  cd grafeas
  ```
  
3. (Optional) If you would like to do development work, run the following:

  ```bash
  git remote add upstream git@github.com:grafeas/grafeas.git
  git remote set-url --push upstream no_push
  ```

_Adding the `upstream` remote sets you up nicely for regularly [syncing your
fork](https://help.github.com/articles/syncing-a-fork/)._

## Authorization

The Grafeas server fails closed: unless it is told how to authorize callers it
denies every request. Authorization is configured under the `grafeas.api.auth`
key of `config.yaml`, and `mode` is one of:

* `deny_all` (the default): every request is denied.
* `policy`: callers are authorized against `policy_file`.
* `insecure_disabled`: authorization is disabled, every client that can reach
  the server can read, modify and delete the notes and occurrences of every
  project. **Never use this outside of tests and local development.**

In `policy` mode a caller is identified by the common name of the client
certificate it authenticates with, so `cafile`, `certfile` and `keyfile` must be
configured as well (see [Use Grafeas with self-signed
certificate](#use-grafeas-with-self-signed-certificate)); the server
certificate must be issued by the configured CA, because the built-in REST
gateway uses it to talk to the gRPC server. Requests without a verified client
certificate carry no identity and are denied.

The policy grants permissions on projects to identities. Anything that is not
granted is denied:

```yaml
bindings:
  - identity: "build-system.example.com"
    projects: ["my-project"]
    permissions: ["projects.get", "notes.create", "occurrences.create"]
  - identity: "admin.example.com"
    projects: ["*"]
    permissions: ["*"]
```

`"*"` is a wildcard that matches any identity, project or permission. Listing
projects is not scoped to a single project, so it requires a binding with a
wildcard project.

## Start Grafeas

The following options will start the Grafeas gRPC and REST APIs on `localhost:8080`.
Note that the shipped configuration denies every request, set
`grafeas.api.auth.mode` to `insecure_disabled` to try the server out locally, or
to `policy` to enforce an authorization policy.

### Using published Docker image

To start the Grafeas server from the publicly published Docker image, do:

```bash
docker pull us.gcr.io/grafeas/grafeas-server:v0.1.0
docker run -p 8080:8080 --name grafeas \
  us.gcr.io/grafeas/grafeas-server:v0.1.0
```

### Using Dockerfile

To start the Grafeas server from the [Dockerfile](../Dockerfile), run the following:

```bash
cd ~/go/src/github.com/grafeas/grafeas
docker build --tag=grafeas .
docker run -p 8080:8080 --name grafeas grafeas
```

In case you see some error during the build which is related to https://github.com/golang/go/issues/37436, you can bypass the kernel issue with:

```
docker build --ulimit memlock=-1 --tag=grafeas .
```

### Using Docker Compose with PostgreSQL

[grafeas-pgsql](https://github.com/grafeas/grafeas-pgsql) provides a way to run
the Grafeas server with PostgreSQL. Please refer to the instructions in the
repository to bring up the stack in your local environment.

### Using `go run`

Run the following:

```shell
cd ~/go/src/github.com/grafeas/grafeas
cd go/v1beta1
go run main/main.go
```

### Testing with `curl`

Run the following in a separate terminal:
```bash
curl https://localhost:8080/v1beta1/projects
```

### Use Grafeas with self-signed certificate

_NOTE: The steps described in this section is meant for development environments._

1. Generate CA:

    ```bash
    openssl genrsa -out ca.key 2048
    openssl req -new -x509 -days 365 -key ca.key -out ca.crt
    ```

1. Create the server key and CSR. Make sure to set `Common Name` to your domain, e.g. `localhost` (without port).

    ```bash
    openssl genrsa -out server.key 2048
    openssl req -new -key server.key -out server.csr
    ```

1. Create self-signed server certificate:

    ```bash
    openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt
    ```
1. Update `config.yaml` by adding the following:

    ```
    cafile: ca.crt
    keyfile: server.key
    certfile: server.crt
    ```
1. Run Grafeas server with the key/cert:

    ```
    go run main/main.go --config config.yaml
    ```

## Access Grafeas API endpoints

### REST API with curl

When using curl with a self signed certificate you need to add `-k/--insecure` and specify the client certificate. To generate the combined certificate, do:

```bash
openssl pkcs12 -export -clcerts -in server.crt -inkey server.key -out server.p12
openssl pkcs12 -in server.p12 -out server.pem -clcerts
```

Now, `curl` the endpoint:

```bash
curl -k --cert server.pem https://localhost:8080/v1beta1/projects
```

### gRPC with a go client

[client.go](../go/v1beta1/example/client.go) contains a small example of a go
client that connects to Grafeas and outputs the notes in `myproject`:

```bash
go run go/v1beta1/example/client.go
```

When using a go client to access Grafeas with a self signed certificate you need to specify the server certificate, server key and the CA certificate. See [cert\_client\.go](../go/v1beta1/example/cert_client/cert_client.go) for an example.

### Enable [CORS](https://enable-cors.org/) on the server

Add the following to your `config.yaml` file below the `api` key:

```
cors\_allowed\_origins:
   - "https://some.example.tld"
   - "https://*.example.net"
```
