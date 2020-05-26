package kong

// FailureMessage all failed request match with this datatype
type FailureMessage struct {
	Message string `json:"message,omitempty"`
}
