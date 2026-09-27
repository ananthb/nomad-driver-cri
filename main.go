// Copyright (c) Ananth Bhaskararaman
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/plugins"
	"go.calculon.tech/nomad-driver-cri/driver"
)

func main() {
	plugins.Serve(factory)
}

// factory returns a new instance of the CRI driver plugin
func factory(log hclog.Logger) any {
	return driver.NewPlugin(log)
}
