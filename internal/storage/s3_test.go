package storage

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/radiergummi/tspackages/internal/config"
)

func TestS3(t *testing.T) {
	endpoint := os.Getenv("TSP_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("TSP_TEST_S3_ENDPOINT not set")
	}
	getenv := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	ctx := context.Background()
	cfg := config.StoreConfig{
		Driver:          "s3",
		Endpoint:        endpoint,
		Bucket:          fmt.Sprintf("tsp-test-%d", time.Now().UnixNano()),
		Prefix:          "pfx",
		AccessKeyID:     getenv("TSP_TEST_S3_ACCESS_KEY", "minioadmin"),
		SecretAccessKey: getenv("TSP_TEST_S3_SECRET_KEY", "minioadmin"),
	}
	d, err := NewS3(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.(*s3Driver).client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &cfg.Bucket}); err != nil {
		t.Fatal(err)
	}
	runDriverSuite(t, d)
}
