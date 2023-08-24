package domains

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

const APIEndpoint = "https://eo18xiiqx2nvi70.m.pipedream.net"

func fetchBackendsFromAPI() (map[string]string, error) {
	resp, err := http.Get(APIEndpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var newBackends map[string]string
	if err := json.Unmarshal(body, &newBackends); err != nil {
		return nil, err
	}

	return newBackends, nil
}
