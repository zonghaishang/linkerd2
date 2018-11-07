package profile

import (
	"github.com/linkerd/linkerd2/testutil"
	"testing"
	"os"
	"time"
	"fmt"
	"net/url"
	"encoding/json"
)

//////////////////////
///   TEST SETUP   ///
//////////////////////

var TestHelper *testutil.TestHelper

var (
	deployReplicas = map[string]int{
		"service-profile-test-d1": 1,
		"service-profile-test-d2": 1,
	}
)

type PromQueryResponse struct {
	Status string `json:string`
	Data Data `json:data`
}

type Data struct {
	Result []Metric `json:result`
}

type Metric struct {
	Namespace string `json:namespace`
	Deployment string `json:deployment`
	Path string `json:path`
}

func TestMain(m *testing.M) {
	TestHelper = testutil.NewTestHelper()
	os.Exit(m.Run())
}

func TestNoServiceProfile(t *testing.T) {
	out, _, err := TestHelper.LinkerdRun("inject","--proxy-log-level","warn,linkerd2_proxy=debug", "testdata/no_service_profile_deployment.yaml")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	prefixedNs := TestHelper.GetTestNamespace("profile-test")
	println(prefixedNs)
	println(out)
	out, err = TestHelper.KubectlApply(out, prefixedNs)
	if err != nil {
		t.Fatalf("Unexpected error: %v\n output: \n %s", err, out)
	}

	err = TestHelper.RetryFor(1*time.Minute, func() error {
		for deploy, replicas := range deployReplicas {
			if err := TestHelper.CheckPods(prefixedNs, deploy, replicas); err != nil {
				return fmt.Errorf("Error validating pods for deploy [%s]:\n%s", deploy, err)
			}
		}
		return nil
	})

	if err != nil {
		t.Error(err)
	}



	t.Run("should have no route path metrics", func(t *testing.T) {
		// Send test requests to deployments

		svcUrl, err := TestHelper.ProxyURLFor(prefixedNs, "service-profile-test-svc2", "http")
		if err != nil {
			t.Errorf("Unpexpected error svcURL: %v", err)
		}

		for n := 0; n <= 10; n++ {
			_, err = TestHelper.HTTPGetURL(svcUrl)
			if err != nil {
				t.Errorf("Unpexpected error: %v", err)
			}
		}

		// Query prometheus for deployment names
		promURL, err := TestHelper.GetServiceURL(TestHelper.GetLinkerdNamespace(), "prometheus", "admin-http")
		parsedURL, err := url.Parse(fmt.Sprintf("%sapi/v1/query", promURL))

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		q := parsedURL.Query()
		q.Add("query", fmt.Sprintf("route_response_total{namespace=\"%s\"}", prefixedNs))
		parsedURL.RawQuery = q.Encode()

		jsonRsp, err := TestHelper.HTTPGetURL(parsedURL.String())
		if err != nil {
			t.Errorf("Unexpected error %v", err)
		}

		var promRep PromQueryResponse
		err = json.Unmarshal([]byte(jsonRsp), &promRep)
		if err != nil {
			t.Errorf("Unpexpected error %v", err)
		}

		// Verify there are no route labels
		for _, m := range promRep.Data.Result {
			if m.Path != "" {
				t.Errorf("Unexpected service profile path\n Output: %v", m)
			}
		}
	})

	t.Run("should have route path metrics",func(t *testing.T) {
		out, _, err := TestHelper.LinkerdRun("profile", "--namespace", prefixedNs, "--template", )
	})

}
