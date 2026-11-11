package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/radiergummi/tspackages/internal/config"
)

type s3Driver struct {
	client *s3.Client
	bucket string
	prefix string // "" or ends in "/"

	bucketOK atomic.Bool // cached positive HeadBucket result
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
	if re, ok := errors.AsType[*awshttp.ResponseError](err); ok {
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

func errCode(err error) string {
	if ae, ok := errors.AsType[smithy.APIError](err); ok {
		return ae.ErrorCode()
	}
	return ""
}

func isNoSuchKey(err error) bool {
	var nsk *types.NoSuchKey
	return errors.As(err, &nsk) || errCode(err) == "NoSuchKey"
}

// bucketCheck returns nil if the bucket exists. A positive result is cached
// for the driver's lifetime.
func (d *s3Driver) bucketCheck(ctx context.Context) error {
	if d.bucketOK.Load() {
		return nil
	}
	if _, err := d.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &d.bucket}); err != nil {
		return fmt.Errorf("storage: bucket %q: %w", d.bucket, err)
	}
	d.bucketOK.Store(true)
	return nil
}

func (d *s3Driver) Get(ctx context.Context, key string) (io.ReadCloser, Info, error) {
	if err := ValidKey(key); err != nil {
		return nil, Info{}, err
	}
	out, err := d.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &d.bucket, Key: d.full(key)})
	if err != nil {
		if isNoSuchKey(err) {
			return nil, Info{}, ErrNotFound
		}
		return nil, Info{}, fmt.Errorf("storage: get %q: %w", key, err)
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
			// HEAD carries no error code: tell a missing key from a missing bucket.
			if berr := d.bucketCheck(ctx); berr != nil {
				return Info{}, berr
			}
			return Info{}, ErrNotFound
		}
		return Info{}, fmt.Errorf("storage: stat %q: %w", key, err)
	}
	return Info{
		Key:     key,
		Size:    aws.ToInt64(out.ContentLength),
		ETag:    cleanETag(out.ETag),
		ModTime: aws.ToTime(out.LastModified),
	}, nil
}

const (
	maxPutAttempts = 5
	minBackoff     = 20 * time.Millisecond
	maxBackoff     = 200 * time.Millisecond
)

// errConflict marks a PutObject that kept hitting 409 conditional conflicts.
var errConflict = errors.New("storage: conditional write conflict persisted")

// put uploads r, optionally conditionally. The body is buffered because
// PutObject needs a seekable payload. 409 conditional conflicts are retried
// with jittered backoff.
func (d *s3Driver) put(ctx context.Context, key string, r io.Reader, ifNoneMatch, ifMatch string) (Info, error) {
	if err := ValidKey(key); err != nil {
		return Info{}, err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return Info{}, err
	}
	for attempt := range maxPutAttempts {
		if attempt > 0 {
			wait := minBackoff + rand.N(maxBackoff-minBackoff)
			select {
			case <-ctx.Done():
				return Info{}, ctx.Err()
			case <-time.After(wait):
			}
		}
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
			return Info{Key: key, Size: int64(len(data)), ETag: cleanETag(out.ETag), ModTime: time.Now().UTC()}, nil
		}
		if status(err) == http.StatusConflict {
			continue
		}
		return Info{}, err
	}
	return Info{}, errConflict
}

// multipartThreshold is the size above which Put uploads a seekable body in
// parts of multipartPartSize instead of buffering it.
const (
	multipartThreshold = 64 << 20
	multipartPartSize  = 16 << 20
)

// sizedReaderAt is a body Put can split into parts without buffering, such as
// an *os.File.
type sizedReaderAt interface {
	io.ReaderAt
	io.Seeker
}

func (d *s3Driver) Put(ctx context.Context, key string, r io.Reader) (Info, error) {
	if ra, ok := r.(sizedReaderAt); ok {
		start, err := ra.Seek(0, io.SeekCurrent)
		if err != nil {
			return Info{}, err
		}
		end, err := ra.Seek(0, io.SeekEnd)
		if err != nil {
			return Info{}, err
		}
		if _, err := ra.Seek(start, io.SeekStart); err != nil {
			return Info{}, err
		}
		if end-start > multipartThreshold {
			info, err := d.putMultipart(ctx, key, io.NewSectionReader(ra, start, end-start))
			if err != nil {
				return Info{}, fmt.Errorf("storage: put %q: %w", key, err)
			}
			return info, nil
		}
	}
	info, err := d.put(ctx, key, r, "", "")
	if err != nil {
		return Info{}, fmt.Errorf("storage: put %q: %w", key, err)
	}
	return info, nil
}

// putMultipart uploads body in parts, each read from body as it is sent, and
// aborts the upload on failure so no parts are left behind.
func (d *s3Driver) putMultipart(ctx context.Context, key string, body *io.SectionReader) (Info, error) {
	if err := ValidKey(key); err != nil {
		return Info{}, err
	}
	created, err := d.client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &d.bucket, Key: d.full(key)})
	if err != nil {
		return Info{}, err
	}
	abort := func() {
		// A fresh context: the upload must be aborted even if ctx is done.
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		_, _ = d.client.AbortMultipartUpload(actx, &s3.AbortMultipartUploadInput{Bucket: &d.bucket, Key: d.full(key), UploadId: created.UploadId}) // best effort; a bucket lifecycle rule cleans up the rest
	}
	var parts []types.CompletedPart
	for off, n := int64(0), int32(1); off < body.Size(); off, n = off+multipartPartSize, n+1 {
		size := min(multipartPartSize, body.Size()-off)
		out, err := d.client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket: &d.bucket, Key: d.full(key), UploadId: created.UploadId, PartNumber: aws.Int32(n),
			Body: io.NewSectionReader(body, off, size), ContentLength: aws.Int64(size),
		})
		if err != nil {
			abort()
			return Info{}, err
		}
		parts = append(parts, types.CompletedPart{ETag: out.ETag, PartNumber: aws.Int32(n)})
	}
	done, err := d.client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket: &d.bucket, Key: d.full(key), UploadId: created.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
	})
	if err != nil {
		abort()
		return Info{}, err
	}
	return Info{Key: key, Size: body.Size(), ETag: cleanETag(done.ETag), ModTime: time.Now().UTC()}, nil
}

func (d *s3Driver) GetRange(ctx context.Context, key string, off, n int64) (io.ReadCloser, error) {
	if err := ValidKey(key); err != nil {
		return nil, err
	}
	rng := fmt.Sprintf("bytes=%d-", off)
	if n >= 0 {
		rng = fmt.Sprintf("bytes=%d-%d", off, off+n-1)
	}
	out, err := d.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &d.bucket, Key: d.full(key), Range: &rng})
	if err != nil {
		if isNoSuchKey(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: get %q: %w", key, err)
	}
	return out.Body, nil
}

func (d *s3Driver) PutIfAbsent(ctx context.Context, key string, r io.Reader) (Info, error) {
	info, err := d.put(ctx, key, r, "*", "")
	switch {
	case err == nil:
		return info, nil
	case status(err) == http.StatusPreconditionFailed:
		return Info{}, ErrExists
	case errors.Is(err, errConflict):
		if _, serr := d.Stat(ctx, key); serr == nil {
			return Info{}, ErrExists
		}
	}
	return Info{}, fmt.Errorf("storage: put-if-absent %q: %w", key, err)
}

func (d *s3Driver) PutIfMatch(ctx context.Context, key string, r io.Reader, etag string) (Info, error) {
	var info Info
	var err error
	if etag == "" {
		info, err = d.put(ctx, key, r, "*", "")
	} else {
		info, err = d.put(ctx, key, r, "", etag)
	}
	switch {
	case err == nil:
		return info, nil
	case status(err) == http.StatusPreconditionFailed:
		return Info{}, ErrPrecondition
	case errors.Is(err, errConflict):
		return Info{}, fmt.Errorf("%w: %w", ErrPrecondition, err)
	case etag != "" && status(err) == http.StatusNotFound:
		// If-Match on a missing key is a 404: a missing key is a failed
		// precondition, a missing bucket is a real error.
		if isNoSuchKey(err) || d.bucketCheck(ctx) == nil {
			return Info{}, ErrPrecondition
		}
	}
	return Info{}, fmt.Errorf("storage: put-if-match %q: %w", key, err)
}

func (d *s3Driver) Delete(ctx context.Context, key string) error {
	if err := ValidKey(key); err != nil {
		return err
	}
	_, err := d.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &d.bucket, Key: d.full(key)})
	if err != nil && !isNoSuchKey(err) {
		return fmt.Errorf("storage: delete %q: %w", key, err)
	}
	return nil
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
