package apt

// RequestError is a client mistake or conflict: Status is 400, 409 or 413 and
// Detail is sent to the client as the response body.
type RequestError struct {
	Status int
	Detail string
}

func (e *RequestError) Error() string { return e.Detail }
