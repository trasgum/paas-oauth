package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/net/context"

	"github.com/stratio/paas-oauth/common"
)

const (
	uiconfigJson = "/opt/mesosphere/etc/ui-config.json"
)

func handleUIConfig(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	f, err := os.Open(uiconfigJson)
	if err != nil {
		return common.NewHttpError("ui-config.json read failed", http.StatusInternalServerError)
	}
	defer f.Close()

	var cfg map[string]interface{}
	err = json.NewDecoder(f).Decode(&cfg)
	if err != nil {
		log.Printf("Decode: %v", err)
		return common.NewHttpError("JSON decode error", http.StatusInternalServerError)
	}

	clusterCfg := make(map[string]interface{})
	clusterCfg["firstUser"] = false
	clusterCfg["id"] = clusterId()
	cfg["clusterConfiguration"] = clusterCfg

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)

	return nil
}

const (
	clusterIdFile = "/var/lib/dcos/cluster-id"
)

func clusterId() string {
	clusterId := ""
	g, err := os.Open(clusterIdFile)
	if err == nil {
		defer g.Close()
		b, err := ioutil.ReadAll(g)
		if err == nil {
			clusterId = strings.TrimSpace(string(b))
		}
	}
	return clusterId
}
