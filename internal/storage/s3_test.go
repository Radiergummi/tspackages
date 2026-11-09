package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/radiergummi/tspackages/internal/config"
)

func testS3Config(t *testing.T) config.StoreConfig {
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
	return config.StoreConfig{
		Driver:          "s3",
		Endpoint:        endpoint,
		Bucket:          fmt.Sprintf("tsp-test-%d", time.Now().UnixNano()),
		Prefix:          "pfx",
		AccessKeyID:     getenv("TSP_TEST_S3_ACCESS_KEY", "minioadmin"),
		SecretAccessKey: getenv("TSP_TEST_S3_SECRET_KEY", "minioadmin"),
	}
}

func TestS3(t *testing.T) {
	ctx := context.Background()
	cfg := testS3Config(t)
	d, err := NewS3(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.(*s3Driver).client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &cfg.Bucket}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := d.(*s3Driver).client
		pager := s3.NewListObjectsV2Paginator(c, &s3.ListObjectsV2Input{Bucket: &cfg.Bucket})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				t.Logf("cleanup list: %v", err)
				return
			}
			for _, o := range page.Contents {
				c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &cfg.Bucket, Key: o.Key})
			}
		}
		if _, err := c.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &cfg.Bucket}); err != nil {
			t.Logf("cleanup bucket: %v", err)
		}
	})
	runDriverSuite(t, d)
}

func TestS3MissingBucket(t *testing.T) {
	ctx := context.Background()
	cfg := testS3Config(t)
	cfg.Bucket = strings.Replace(cfg.Bucket, "tsp-test", "tsp-absent", 1)
	d, err := NewS3(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.Get(ctx, "k"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("Get: %v", err)
	}
	if _, err := d.Stat(ctx, "k"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("Stat: %v", err)
	}
	if _, err := d.PutIfMatch(ctx, "k", strings.NewReader("x"), "abc"); err == nil || errors.Is(err, ErrPrecondition) {
		t.Errorf("PutIfMatch: %v", err)
	}
}
