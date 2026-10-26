package credentials

import (
	"fmt"
	"os"
)

// EnvSecrets reads secrets from the process environment.
//
// A process's environment is fixed when it starts: changing a variable in a
// shell, .env file or compose file does NOT reach a running container. To
// rotate an environment-backed secret the container must be recreated
// (docker compose up -d). Use password_file for rotation without restarts.
type EnvSecrets struct{}

func NewEnvSecrets() *EnvSecrets { return &EnvSecrets{} }

func (*EnvSecrets) Get(name string) (string, error) {
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return "", fmt.Errorf("environment variable %s is not set", name)
	}
	return v, nil
}
