consul-kube
===========

[![Build status](https://travis-ci.org/tradel/consul-kube.svg?master)](https://travis-ci.org/tradel)

This is a utility that performs a few useful functions against Consul running in Kubernetes. 


## Requirements

 * Python 3.6
 * A working kube setup with a valid `$HOME/.kube/config`


## Installation

You can install this utility from PyPI using a recent version of pip:

        pip install consul-kube 
        

## Usage

The `consul-kube` command line interface accepts several options and commands. To see them all, run
`consul-kube -help`:

        Usage: consul-kube [OPTIONS] COMMAND [ARGS]...
        
        Options:
          -debug / -no-debug            Enables or disables verbose output.
          -save-certs / -no-save-certs  Save a copy of any retrieved certs.
          -context TEXT                 Choose a context from your kubeconfig.
          -version                      Show the version and exit.
          -help                         Show this message and exit.
          --help                        Show this message and exit.
        
        Commands:
          rotate    Forces the Consul Connect CA to rotate its root certificate.
          validate  Checks the certificates for every injected pod.

Some of the commands accept additional options. To see the options for a particular command, run
`consul-kube COMMAND -help`.

### Validating certificates

### Rotating the CA root certificate
