# log4jscanner

[![Go Reference](https://pkg.go.dev/badge/github.com/google/log4jscanner/jar.svg)](https://pkg.go.dev/github.com/google/log4jscanner/jar)

A minor fork of https://github.com/google/log4jscanner

## Changes

- The scanner won't detect patched version 2.12.2+ and 2.3.1+
- The scanner scan all local disks if no argument is given
- The scanner checks .par, .sar , .kar
- The scanner will output to stdout the result as CSV with the following format:

``"hostname","path","version"``

## Installing

Pre-compiled binaries are available as [release assets][releases].

To install from source with an existing [Go][go] v1.17+ installation, either
use [go install][go-install]:

```
go install github.com/nikaiw/log4jscanner@latest
```

Or build from the repo directly:

```
git clone https://github.com/nikaiw/log4jscanner.git
cd log4jscanner
go build -o log4jscanner
```

