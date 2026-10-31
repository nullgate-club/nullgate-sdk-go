// Package turn observes a relay through an explicit caller-selected TCP route.
package turn

// Server is the configuration issued by the profiling source, not the proxy.
type Server struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Transport  string `json:"transport"`
	Username   string `json:"username"`
	Credential string `json:"credential"`
}

// Candidate retains the actual relay address and observation time.
type Candidate struct {
	Value     string  `json:"value"`
	ElapsedMS float64 `json:"elapsed_ms"`
}

// Observation contains only the candidate facts supplied by the TURN provider.
type Observation struct {
	Candidates   []Candidate `json:"candidates"`
	CompleteAtMS float64     `json:"complete_at_ms"`
}
