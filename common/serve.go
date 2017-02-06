package common

import (
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/codegangsta/cli"
	"golang.org/x/net/context"
)

func ReadLine(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimSpace(string(b))), nil
}

func ServeCmd(c *cli.Context, ctx context.Context, routes map[string]map[string]Handler) error {
	r := NewRouter(ctx, routes)
	return http.ListenAndServe(c.String("addr"), r)
}
