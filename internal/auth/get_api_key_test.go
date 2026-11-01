package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers http.Header
		wantKey string
		wantErr error
		anyErr  bool
	}{
		"valid header": {
			headers: http.Header{"Authorization": []string{"ApiKey abc123"}},
			wantKey: "abc123",
		},
		"no header": {
			headers: http.Header{},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		"empty header value": {
			headers: http.Header{"Authorization": []string{""}},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		"wrong scheme": {
			headers: http.Header{"Authorization": []string{"Bearer abc123"}},
			anyErr:  true,
		},
		"missing key": {
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			anyErr:  true,
		},
		"lowercase scheme": {
			headers: http.Header{"Authorization": []string{"apikey abc123"}},
			anyErr:  true,
		},
		"extra parts uses first token": {
			headers: http.Header{"Authorization": []string{"ApiKey abc123 extra"}},
			wantKey: "abc123",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.headers)

			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected error %v, got %v", tc.wantErr, err)
				}
			case tc.anyErr:
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
			default:
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if got != tc.wantKey {
				t.Errorf("expected key %q, got %q", tc.wantKey, got)
			}
		})
	}
}
