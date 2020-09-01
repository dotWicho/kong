# marathon

[![Go](https://github.com/dotWicho/kong/workflows/Go/badge.svg?branch=master)](https://github.com/dotWicho/kong)
[![Quality Report](https://goreportcard.com/badge/github.com/dotWicho/kong)](https://goreportcard.com/badge/github.com/dotWicho/kong)
[![GoDoc](https://godoc.org/github.com/dotWicho/kong?status.svg)](https://pkg.go.dev/github.com/dotWicho/kong?tab=doc)

## Library to manage [Kong](https://konghq.com/) servers via API Calls

## Getting started

- API documentation is available via [godoc](https://godoc.org/github.com/dotWicho/kong).
- Test code contains some small examples of the use of this library.

## Installation

To install Kong package, you need to install Go and set your Go workspace first.

1 - The first need [Go](https://golang.org/) installed (**version 1.13+ is required**).
Then you can use the below Go command to install Kong

```bash
$ go get -u github.com/dotWicho/kong
```

And then Import it in your code:

``` go
package main

import "github.com/dotWicho/kong"
```
Or

2 - Use as module in you project (go.mod file):

``` go
module myclient

go 1.13

require (
	github.com/dotWicho/kong v1.2.5
)
```

## Contributing

- Get started by checking our [contribution guidelines](https://github.com/dotWicho/kong/blob/master/CONTRIBUTING.md).
- Read the [dotWicho kong wiki](https://github.com/dotWicho/kong/wiki) for more technical and design details.
- If you have any questions, just ask!

