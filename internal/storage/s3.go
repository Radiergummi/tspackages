package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/radiergummi/tspackages/internal/config"
)

type s3Driver struct {
	client *s3.Client
	bucket string
	prefix string // "" or ends in "/"
}

// NewS3 returns a driver backed by an S3-compatible bucket. A custom endpoint
// (MinIO, R2) uses path-style addressing. It does not contact the service.
func NewS3(ctx context.Context, c config.StoreConfig) (Driver, error) {
	if c.Bucket == "" {
		return nil, errors.New("storage: s3 bucket is required")
	}
	region := c.Region
	if region == "" {
		region = "us-east-1"
	}
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	if c.AccessKeyID != "" || c.SecretAccessKey != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, "")))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if c.Endpoint != "" {
			o.BaseEndpoint = aws.String(c.Endpoint)
			o.UsePathStyle = true
			// Third-party stores do not all accept the SDK's default checksums.
			o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
			o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
		}
	})
	prefix := strings.Trim(c.Prefix, "/")
	if prefix != "" {
		prefix += "/"
	}
	return &s3Driver{client: client, bucket: c.Bucket, prefix: prefix}, nil
}

func (d *s3Driver) full(key string) *string { return aws.String(d.prefix + key) }

func status(err error) int {
	var re *awshttp.ResponseError
	if errors.As(err, &re) {
		return re.HTTPStatusCode()
	}
	return 0
}

func cleanETag(e *string) string { return strings.Trim(aws.ToString(e), `"`) }

func quoteETag(e string) string {
	if strings.HasPrefix(e, `"`) || strings.HasPrefix(e, "W/") {
		return e
	}
	return `"` + e + `"`
}

func (d *s3Driver) Get(ctx context.Context, key string) (io.ReadCloser, Info, error) {
	if err := ValidKey(key); err != nil {
		return nil, Info{}, err
	}
	out, err := d.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &d.bucket, Key: d.full(key)})
	if err != nil {
		if status(err) == http.StatusNotFound {
			return nil, Info{}, ErrNotFound
		}
		return nil, Info{}, err
	}
	return out.Body, Info{
		Key:     key,
		Size:    aws.ToInt64(out.ContentLength),
		ETag:    cleanETag(out.ETag),
		ModTime: aws.ToTime(out.LastModified),
	}, nil
}

func (d *s3Driver) Stat(ctx context.Context, key string) (Info, error) {
	if err := ValidKey(key); err != nil {
		return Info{}, err
	}
	out, err := d.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &d.bucket, Key: d.full(key)})
	if err != nil {
		if status(err) == http.StatusNotFound {
			return Info{}, ErrNotFound
		}
		return Info{}, err
	}
	return Info{
		Key:     key,
		Size:    aws.ToInt64(out.ContentLength),
		ETag:    cleanETag(out.ETag),
		ModTime: aws.ToTime(out.LastModified),
	}, nil
}

// put uploads r, optionally conditionally. The body is buffered because
// PutObject needs a seekable payload; a 409 conditional conflict is retried
// once.
func (d *s3Driver) put(ctx context.Context, key string, r io.Reader, ifNoneMatch, ifMatch string) (Info, error) {
	if err := ValidKey(key); err != nil {
		return Info{}, err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return Info{}, err
	}
	for attempt := 0; ; attempt++ {
		in := &s3.PutObjectInput{
			Bucket:        &d.bucket,
			Key:           d.full(key),
			Body:          bytes.NewReader(data),
			ContentLength: aws.Int64(int64(len(data))),
		}
		if ifNoneMatch != "" {
			in.IfNoneMatch = aws.String(ifNoneMatch)
		}
		if ifMatch != "" {
			in.IfMatch = aws.String(quoteETag(ifMatch))
		}
		out, err := d.client.PutObject(ctx, in)
		if err == nil {
			return Info{Key: key, Size: int64(len(data)), ETag: cleanETag(out.ETag)}, nil
		}
		if status(err) == http.StatusConflict && attempt == 0 {
			continue
		}
		return Info{}, err
	}
}

func (d *s3Driver) Put(ctx context.Context, key string, r io.Reader) (Info, error) {
	return d.put(ctx, key, r, "", "")
}

func (d *s3Driver) PutIfAbsent(ctx context.Context, key string, r io.Reader) (Info, error) {
	info, err := d.put(ctx, key, r, "*", "")
	if status(err) == http.StatusPreconditionFailed {
		return Info{}, ErrExists
	}
	return info, err
}

func (d *s3Driver) PutIfMatch(ctx context.Context, key string, r io.Reader, etag string) (Info, error) {
	var info Info
	var err error
	if etag == "" {
		info, err = d.put(ctx, key, r, "*", "")
	} else {
		info, err = d.put(ctx, key, r, "", etag)
	}
	// If-Match on a missing key yields 404 on AWS and 412 elsewhere.
	if s := status(err); s == http.StatusPreconditionFailed || (etag != "" && s == http.StatusNotFound) {
		return Info{}, ErrPrecondition
	}
	return info, err
}

func (d *s3Driver) Delete(ctx context.Context, key string) error {
	if err := ValidKey(key); err != nil {
		return err
	}
	_, err := d.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &d.bucket, Key: d.full(key)})
	if status(err) == http.StatusNotFound {
		return nil
	}
	return err
}

func (d *s3Driver) List(ctx context.Context, prefix string) iter.Seq2[Info, error] {
	return func(yield func(Info, error) bool) {
		if err := validPrefix(prefix); err != nil {
			yield(Info{}, err)
			return
		}
		pager := s3.NewListObjectsV2Paginator(d.client, &s3.ListObjectsV2Input{
			Bucket: &d.bucket,
			Prefix: aws.String(d.prefix + prefix),
		})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				yield(Info{}, fmt.Errorf("storage: list %q: %w", prefix, err))
				return
			}
			for _, o := range page.Contents {
				info := Info{
					Key:     strings.TrimPrefix(aws.ToString(o.Key), d.prefix),
					Size:    aws.ToInt64(o.Size),
					ETag:    cleanETag(o.ETag),
					ModTime: aws.ToTime(o.LastModified),
				}
				if !yield(info, nil) {
					return
				}
			}
		}
	}
}
