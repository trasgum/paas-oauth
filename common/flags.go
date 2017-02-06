package common

import (
	"github.com/codegangsta/cli"
)

var (
	FlAddr = cli.StringFlag{
		Name:  "addr",
		Usage: "<ip>:<port> to listen on",
		Value: "127.0.0.1:8101",
	}
)
