package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// UnionAgent combines multiple upstream SSH agents, forwarding requests in order.
type UnionAgent struct {
	upstreamSockets []string
}

// NewUnionAgent creates a new UnionAgent with the given upstream socket paths.
func NewUnionAgent(sockets []string) *UnionAgent {
	return &UnionAgent{upstreamSockets: sockets}
}

// connectToUpstream connects to an upstream agent socket.
func (u *UnionAgent) connectToUpstream(socketPath string) (agent.ExtendedAgent, net.Conn, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, nil, err
	}
	return agent.NewClient(conn), conn, nil
}

// List returns the union of all keys from all upstream agents.
func (u *UnionAgent) List() ([]*agent.Key, error) {
	var allKeys []*agent.Key
	seen := make(map[string]bool)

	for _, socketPath := range u.upstreamSockets {
		upstream, conn, err := u.connectToUpstream(socketPath)
		if err != nil {
			log.Printf("Warning: failed to connect to upstream %s: %v", socketPath, err)
			continue
		}
		defer conn.Close()

		keys, err := upstream.List()
		if err != nil {
			log.Printf("Warning: failed to list keys from %s: %v", socketPath, err)
			continue
		}

		for _, key := range keys {
			keyID := string(key.Blob)
			if !seen[keyID] {
				seen[keyID] = true
				allKeys = append(allKeys, key)
			}
		}
	}

	return allKeys, nil
}

// Sign tries to sign with each upstream agent in order until one succeeds.
func (u *UnionAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return u.SignWithFlags(key, data, 0)
}

// SignWithFlags tries to sign with flags using each upstream agent in order.
func (u *UnionAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	keyBlob := key.Marshal()

	for _, socketPath := range u.upstreamSockets {
		upstream, conn, err := u.connectToUpstream(socketPath)
		if err != nil {
			log.Printf("Warning: failed to connect to upstream %s: %v", socketPath, err)
			continue
		}

		sig, err := upstream.SignWithFlags(key, data, flags)
		conn.Close()
		if err == nil {
			return sig, nil
		}

		// Check if this agent has the key
		keys, listErr := upstream.List()
		if listErr != nil {
			continue
		}

		hasKey := false
		for _, k := range keys {
			if string(k.Blob) == string(keyBlob) {
				hasKey = true
				break
			}
		}

		if hasKey {
			// Agent has the key but signing failed
			log.Printf("Warning: signing failed with upstream %s: %v", socketPath, err)
		}
	}

	return nil, fmt.Errorf("no upstream agent could sign with the requested key")
}

// Add forwards add requests to the first upstream agent.
func (u *UnionAgent) Add(key agent.AddedKey) error {
	if len(u.upstreamSockets) == 0 {
		return fmt.Errorf("no upstream agents configured")
	}

	upstream, conn, err := u.connectToUpstream(u.upstreamSockets[0])
	if err != nil {
		return err
	}
	defer conn.Close()

	return upstream.Add(key)
}

// Remove forwards remove requests to all upstream agents.
func (u *UnionAgent) Remove(key ssh.PublicKey) error {
	var lastErr error
	for _, socketPath := range u.upstreamSockets {
		upstream, conn, err := u.connectToUpstream(socketPath)
		if err != nil {
			lastErr = err
			continue
		}

		err = upstream.Remove(key)
		conn.Close()
		if err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// RemoveAll forwards remove-all requests to all upstream agents.
func (u *UnionAgent) RemoveAll() error {
	var lastErr error
	for _, socketPath := range u.upstreamSockets {
		upstream, conn, err := u.connectToUpstream(socketPath)
		if err != nil {
			lastErr = err
			continue
		}

		err = upstream.RemoveAll()
		conn.Close()
		if err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// Lock forwards lock requests to all upstream agents.
func (u *UnionAgent) Lock(passphrase []byte) error {
	var lastErr error
	for _, socketPath := range u.upstreamSockets {
		upstream, conn, err := u.connectToUpstream(socketPath)
		if err != nil {
			lastErr = err
			continue
		}

		err = upstream.Lock(passphrase)
		conn.Close()
		if err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// Unlock forwards unlock requests to all upstream agents.
func (u *UnionAgent) Unlock(passphrase []byte) error {
	var lastErr error
	for _, socketPath := range u.upstreamSockets {
		upstream, conn, err := u.connectToUpstream(socketPath)
		if err != nil {
			lastErr = err
			continue
		}

		err = upstream.Unlock(passphrase)
		conn.Close()
		if err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// Signers returns signers for all keys from all upstream agents.
func (u *UnionAgent) Signers() ([]ssh.Signer, error) {
	var allSigners []ssh.Signer
	seen := make(map[string]bool)

	for _, socketPath := range u.upstreamSockets {
		upstream, conn, err := u.connectToUpstream(socketPath)
		if err != nil {
			log.Printf("Warning: failed to connect to upstream %s: %v", socketPath, err)
			continue
		}
		defer conn.Close()

		signers, err := upstream.Signers()
		if err != nil {
			log.Printf("Warning: failed to get signers from %s: %v", socketPath, err)
			continue
		}

		for _, signer := range signers {
			keyID := string(signer.PublicKey().Marshal())
			if !seen[keyID] {
				seen[keyID] = true
				allSigners = append(allSigners, signer)
			}
		}
	}

	return allSigners, nil
}

// Extension forwards extension requests to each upstream agent until one succeeds.
func (u *UnionAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	for _, socketPath := range u.upstreamSockets {
		upstream, conn, err := u.connectToUpstream(socketPath)
		if err != nil {
			continue
		}

		result, err := upstream.Extension(extensionType, contents)
		conn.Close()
		if err == nil {
			return result, nil
		}
	}
	return nil, agent.ErrExtensionUnsupported
}

// generateSocketPath creates a socket path following the ssh-agent convention:
// $TMPDIR/ssh-XXXXXXXXXX/agent.<ppid>
func generateSocketPath() (string, error) {
	tmpdir := os.TempDir()

	// Generate 10 random hex characters (5 bytes = 10 hex chars)
	randBytes := make([]byte, 5)
	if _, err := rand.Read(randBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	randStr := hex.EncodeToString(randBytes)

	// Create directory: $TMPDIR/ssh-XXXXXXXXXX
	dirName := fmt.Sprintf("ssh-%s", randStr)
	dirPath := filepath.Join(tmpdir, dirName)

	if err := os.MkdirAll(dirPath, 0700); err != nil {
		return "", fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Socket name: agent.<ppid>
	socketName := fmt.Sprintf("agent.%d", os.Getppid())
	return filepath.Join(dirPath, socketName), nil
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: %s [-socket <path>] <upstream-socket>...

Options:
`, os.Args[0])
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, `
Arguments:
  upstream-socket  One or more paths to upstream SSH agent sockets
`)
}

func main() {
	socketPath := flag.String("socket", "", "Path for the union agent's socket (auto-generated if not specified)")
	flag.Usage = usage
	flag.Parse()

	upstreamSockets := flag.Args()
	if len(upstreamSockets) == 0 {
		usage()
		os.Exit(1)
	}

	// Generate socket path if not specified
	actualSocketPath := *socketPath
	var socketDir string
	if actualSocketPath == "" {
		var err error
		actualSocketPath, err = generateSocketPath()
		if err != nil {
			log.Fatalf("Failed to generate socket path: %v", err)
		}
		socketDir = filepath.Dir(actualSocketPath)
	}

	// Remove existing socket if present
	if err := os.RemoveAll(actualSocketPath); err != nil {
		log.Fatalf("Failed to remove existing socket: %v", err)
	}

	listener, err := net.Listen("unix", actualSocketPath)
	if err != nil {
		log.Fatalf("Failed to listen on socket %s: %v", actualSocketPath, err)
	}
	defer listener.Close()

	// Set socket permissions
	if err := os.Chmod(actualSocketPath, 0600); err != nil {
		log.Fatalf("Failed to set socket permissions: %v", err)
	}

	unionAgent := NewUnionAgent(upstreamSockets)

	// Print in ssh-agent compatible format for eval
	fmt.Printf("SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n", actualSocketPath)
	fmt.Printf("SSH_AGENT_PID=%d; export SSH_AGENT_PID;\n", os.Getpid())
	fmt.Printf("echo Agent pid %d;\n", os.Getpid())

	log.Printf("Union SSH agent listening on %s", actualSocketPath)
	log.Printf("Forwarding to upstream agents: %v", upstreamSockets)

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	shutdownCh := make(chan bool, 1)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case clean := <-shutdownCh:
					if clean {
						// Clean shutdown requested, exit quietly
						return
					}
				default:
				}
				log.Printf("Accept error: %v", err)
				return
			}

			go func(c net.Conn) {
				defer c.Close()
				if err := agent.ServeAgent(unionAgent, c); err != nil && err != io.EOF {
					log.Printf("Agent serve error: %v", err)
				}
			}(conn)
		}
	}()

	<-sigCh
	log.Println("Shutting down...")
	shutdownCh <- true
	listener.Close()
	os.Remove(actualSocketPath)
	if socketDir != "" {
		os.Remove(socketDir) // Clean up the directory we created
	}
}
