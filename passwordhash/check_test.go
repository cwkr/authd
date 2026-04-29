package passwordhash

import "testing"

func TestGetFormat(t *testing.T) {
	tests := []struct {
		hash string
		want string
	}{
		{
			hash: "$2a$07$KtihyzNr6vgSuNdrYdo2AeyBHRDM2txVOrXeU9XprR71eUL4hI2/2",
			want: "bcrypt",
		},
		{
			hash: "{SSHA}aJ47Itzw6UOvxVOikvFEnUfUCNA4LmA3I7ZAsA==",
			want: "SSHA",
		},
		{
			hash: "{SSHA256}7nOk8eSzDNw0FgBjpmhHwdc8bzSLGFDq+gT9PqYSS88izmW30luqKza51sv3lyok",
			want: "SSHA256",
		},
		{
			hash: "{SSHA512}gZeM9Oj6xuaDIwfQtcbPzxnnOpyoRyF/N6Psk7pi+TLifhSRuMMqAyKwdeDrC+Th0igQ8DZjugRVHOJST47j4qCptCodTOu2DhjofbdvmTM=",
			want: "SSHA512",
		},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := GetFormat(tt.hash); got != tt.want {
				t.Errorf("GetFormat(%q) = %q, want %q", tt.hash, got, tt.want)
			}
		})
	}
}

func TestCheck(t *testing.T) {
	password := "Pa$$w0rd"
	tests := []string{
		"$2a$07$KtihyzNr6vgSuNdrYdo2AeyBHRDM2txVOrXeU9XprR71eUL4hI2/2",
		"{SSHA}aJ47Itzw6UOvxVOikvFEnUfUCNA4LmA3I7ZAsA==",
		"{SSHA256}7nOk8eSzDNw0FgBjpmhHwdc8bzSLGFDq+gT9PqYSS88izmW30luqKza51sv3lyok",
		"{SSHA512}gZeM9Oj6xuaDIwfQtcbPzxnnOpyoRyF/N6Psk7pi+TLifhSRuMMqAyKwdeDrC+Th0igQ8DZjugRVHOJST47j4qCptCodTOu2DhjofbdvmTM=",
	}
	for _, hash := range tests {
		t.Run(GetFormat(hash), func(t *testing.T) {
			if got := Check(hash, password); got != nil {
				t.Errorf("Check(%q, %q) = %q, want nil", password, hash, got)
			}
		})
	}
}
