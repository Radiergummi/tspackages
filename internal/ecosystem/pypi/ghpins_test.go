package pypi

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/githubapp"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/testutil"
)

func fsDriver(t *testing.T) storage.Driver {
	t.Helper()
	d, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// s3Driver returns a driver on a fresh bucket of the S3 test service,
// emptied and removed after the test; it skips without the service.
func s3Driver(t *testing.T) storage.Driver {
	t.Helper()
	endpoint, accessKey, secretKey, bucket := testutil.S3Env(t)
	ctx := context.Background()
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")))
	if err != nil {
		t.Fatal(err)
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) { o.BaseEndpoint = aws.String(endpoint); o.UsePathStyle = true })
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pager := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{Bucket: &bucket})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				t.Logf("list %s: %v", bucket, err)
				return
			}
			for _, o := range page.Contents {
				client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: o.Key})
			}
		}
		client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
	})
	d, err := storage.Open(ctx, config.StoreConfig{Driver: "s3", Endpoint: endpoint, Bucket: bucket, AccessKeyID: accessKey, SecretAccessKey: secretKey})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// drivers runs f against the fs driver and, when the S3 test service is
// configured, against S3.
func drivers(t *testing.T, f func(t *testing.T, d storage.Driver)) {
	t.Run("fs", func(t *testing.T) { f(t, fsDriver(t)) })
	t.Run("s3", func(t *testing.T) { f(t, s3Driver(t)) })
}

func TestPinOwnerFirstWins(t *testing.T) {
	drivers(t, func(t *testing.T, d storage.Driver) {
		ctx := context.Background()
		p := newGHPins(d, "gh")
		a := githubapp.Repo{ID: 1, FullName: "acme/a"}
		b := githubapp.Repo{ID: 2, FullName: "acme/b"}
		if got, err := p.PinOwner(ctx, "acme-lib", a); err != nil || got != 1 {
			t.Fatalf("first: %d %v", got, err)
		}
		if got, err := p.PinOwner(ctx, "acme-lib", b); err != nil || got != 1 {
			t.Fatalf("second: %d %v", got, err)
		}
		// A fresh instance reads the stored pin, not a cache.
		owners, err := newGHPins(d, "gh").Owners(ctx)
		if err != nil || len(owners) != 1 || owners["acme-lib"] != 1 {
			t.Fatalf("owners: %v %v", owners, err)
		}
		if _, err := d.Stat(ctx, "pypi-github/gh/owners/"+storage.EscapeSegment("acme-lib")+".json"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPinOwnerAfterOperatorDelete(t *testing.T) {
	drivers(t, func(t *testing.T, d storage.Driver) {
		ctx := context.Background()
		p := newGHPins(d, "gh")
		if _, err := p.PinOwner(ctx, "acme-lib", githubapp.Repo{ID: 1, FullName: "acme/a"}); err != nil {
			t.Fatal(err)
		}
		if err := d.Delete(ctx, "pypi-github/gh/owners/"+storage.EscapeSegment("acme-lib")+".json"); err != nil {
			t.Fatal(err)
		}
		owners, err := p.Owners(ctx)
		if err != nil || len(owners) != 0 {
			t.Fatalf("owners after delete: %v %v", owners, err)
		}
		if got, err := p.PinOwner(ctx, "acme-lib", githubapp.Repo{ID: 2, FullName: "acme/b"}); err != nil || got != 2 {
			t.Fatalf("repin: %d %v", got, err)
		}
	})
}

func TestPinOwnerCorruptSkipped(t *testing.T) {
	d := fsDriver(t)
	ctx := context.Background()
	if _, err := d.Put(ctx, "pypi-github/gh/owners/"+storage.EscapeSegment("bad")+".json", strings.NewReader("{")); err != nil {
		t.Fatal(err)
	}
	p := newGHPins(d, "gh")
	if _, err := p.PinOwner(ctx, "good", githubapp.Repo{ID: 3, FullName: "a/b"}); err != nil {
		t.Fatal(err)
	}
	owners, err := p.Owners(ctx)
	if err != nil || len(owners) != 1 || owners["good"] != 3 {
		t.Fatalf("owners: %v %v", owners, err)
	}
}

func TestPinDigestFirstWins(t *testing.T) {
	drivers(t, func(t *testing.T, d storage.Driver) {
		ctx := context.Background()
		p := newGHPins(d, "gh")
		a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
		if got, err := p.PinDigest(ctx, 42, a, 10); err != nil || got != a {
			t.Fatalf("first: %q %v", got, err)
		}
		if got, err := p.PinDigest(ctx, 42, b, 10); err != nil || got != a {
			t.Fatalf("second: %q %v", got, err)
		}
		digests, err := newGHPins(d, "gh").Digests(ctx)
		if err != nil || len(digests) != 1 || digests[42] != a {
			t.Fatalf("digests: %v %v", digests, err)
		}
		if _, err := d.Stat(ctx, "pypi-github/gh/digests/42.json"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPinDigestInvalidRefused(t *testing.T) {
	p := newGHPins(fsDriver(t), "gh")
	for _, bad := range []string{"", "sha256:" + strings.Repeat("a", 64), strings.Repeat("A", 64), strings.Repeat("a", 63)} {
		if _, err := p.PinDigest(context.Background(), 1, bad, 1); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
