//go:build e2e

package e2e_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"dev-utilities/pkg/apierror"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// E2ETestSuite contains end-to-end tests using Docker containers
type E2ETestSuite struct {
	suite.Suite
	containerID   string
	imageName     string
	baseURL       string
	httpClient    *http.Client
	cleanupFailed bool
}

// SetupSuite runs once before all tests
func (suite *E2ETestSuite) SetupSuite() {
	// Skip E2E tests if Docker is not available or if running in CI without Docker
	if !suite.isDockerAvailable() {
		suite.T().Skip("Docker not available, skipping E2E tests")
	}
	
	// Set image name for cleanup tracking
	suite.imageName = "dev-utilities:test"
	
	// Build Docker image
	suite.T().Log("Building Docker image...")
	err := suite.buildDockerImage()
	require.NoError(suite.T(), err, "Failed to build Docker image")
	
	// Set up HTTP client first
	suite.httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}
	
	// Start container
	suite.T().Log("Starting Docker container...")
	containerID, err := suite.startContainer()
	require.NoError(suite.T(), err, "Failed to start container")
	suite.containerID = containerID
	
	// Wait for container to be ready
	suite.T().Log("Waiting for container to be ready...")
	err = suite.waitForContainer()
	require.NoError(suite.T(), err, "Container failed to start properly")
	
	// Set up signal handler for graceful cleanup on interruption
	suite.setupSignalHandler()
	
	suite.T().Log("E2E test setup complete")
}

// SetupTest runs before each individual test
func (suite *E2ETestSuite) SetupTest() {
	// Verify container is still running before each test
	if suite.containerID != "" {
		cmd := exec.Command("docker", "ps", "-q", "--filter", fmt.Sprintf("id=%s", suite.containerID))
		output, err := cmd.Output()
		if err != nil || strings.TrimSpace(string(output)) == "" {
			suite.T().Fatalf("Container %s is not running. Test environment is compromised.", suite.containerID)
		}
	}
}

// TearDownTest runs after each individual test (for cleanup if test fails)
func (suite *E2ETestSuite) TearDownTest() {
	// This method can be used for per-test cleanup if needed
	// Currently, we rely on suite-level cleanup, but this provides a hook
	// for future per-test cleanup requirements
}

// TearDownSuite runs once after all tests
func (suite *E2ETestSuite) TearDownSuite() {
	suite.T().Log("Starting comprehensive cleanup of Docker artifacts...")
	
	// Perform comprehensive cleanup
	suite.performComprehensiveCleanup()
	
	// Final verification of cleanup
	suite.verifyCleanupSuccess()
	
	// Final warning if cleanup failed
	if suite.cleanupFailed {
		suite.T().Log("⚠️  WARNING: Some cleanup operations failed. Manual cleanup may be required.")
		suite.T().Log("   Run the following commands to clean up manually:")
		if suite.containerID != "" {
			suite.T().Logf("   docker stop %s", suite.containerID)
			suite.T().Logf("   docker rm %s", suite.containerID)
		}
		if suite.imageName != "" {
			suite.T().Logf("   docker rmi %s", suite.imageName)
		}
		suite.T().Log("   docker system prune -f")
	} else {
		suite.T().Log("✅ All Docker artifacts cleaned up successfully")
	}
}

// isDockerAvailable checks if Docker is available
func (suite *E2ETestSuite) isDockerAvailable() bool {
	cmd := exec.Command("docker", "version")
	err := cmd.Run()
	return err == nil
}

// buildDockerImage builds the Docker image for testing
func (suite *E2ETestSuite) buildDockerImage() error {
	cmd := exec.Command("docker", "build", "-t", suite.imageName, "..")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// startContainer starts a Docker container and returns its ID
func (suite *E2ETestSuite) startContainer() (string, error) {
	// Use a random port to avoid conflicts
	port, err := suite.getAvailablePort()
	if err != nil {
		return "", fmt.Errorf("failed to get available port: %w", err)
	}
	suite.baseURL = fmt.Sprintf("http://localhost:%s", port)
	
	cmd := exec.Command("docker", "run", "-d", 
		"-p", fmt.Sprintf("%s:8080", port),
		"-e", "SERVER_PORT=8080",
		"-e", "LOG_LEVEL=info",
		"-e", "AUTH_METHOD=none",
		"-e", "RATE_LIMIT_ENABLED=false",
		suite.imageName)
	
	output, err := cmd.Output()
	if err != nil {
		// Get stderr for more detailed error information
		if exitError, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("failed to start container: %w, stderr: %s", err, string(exitError.Stderr))
		}
		return "", fmt.Errorf("failed to start container: %w", err)
	}
	
	containerID := strings.TrimSpace(string(output))
	return containerID, nil
}

// getAvailablePort finds an available port for testing
func (suite *E2ETestSuite) getAvailablePort() (string, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return "", err
	}
	defer listener.Close()
	
	addr := listener.Addr().(*net.TCPAddr)
	return fmt.Sprintf("%d", addr.Port), nil
}

// waitForContainer waits for the container to be ready
func (suite *E2ETestSuite) waitForContainer() error {
	maxAttempts := 30
	for i := 0; i < maxAttempts; i++ {
		resp, err := suite.httpClient.Get(suite.baseURL + "/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		
		time.Sleep(1 * time.Second)
	}
	
	return fmt.Errorf("container did not become ready within %d seconds", maxAttempts)
}

// stopContainer stops and removes the Docker container
func (suite *E2ETestSuite) stopContainer() {
	if suite.containerID != "" {
		suite.T().Logf("Stopping container %s...", suite.containerID)
		if err := exec.Command("docker", "stop", suite.containerID).Run(); err != nil {
			suite.T().Logf("Warning: Failed to stop container %s: %v", suite.containerID, err)
			suite.cleanupFailed = true
		}
		
		suite.T().Logf("Removing container %s...", suite.containerID)
		if err := exec.Command("docker", "rm", suite.containerID).Run(); err != nil {
			suite.T().Logf("Warning: Failed to remove container %s: %v", suite.containerID, err)
			suite.cleanupFailed = true
		}
	}
}

// performComprehensiveCleanup performs thorough cleanup of all Docker artifacts
func (suite *E2ETestSuite) performComprehensiveCleanup() {
	// 1. Stop and remove the main container
	suite.stopContainer()
	
	// 2. Find and clean up any orphaned containers from this test image
	suite.cleanupOrphanedContainers()
	
	// 3. Remove the test Docker image
	suite.removeTestImage()
	
	// 4. Clean up any dangling images and build cache
	suite.cleanupDanglingArtifacts()
}

// cleanupOrphanedContainers finds and removes any containers created from the test image
func (suite *E2ETestSuite) cleanupOrphanedContainers() {
	suite.T().Log("Checking for orphaned containers...")
	
	// Find containers created from our test image
	cmd := exec.Command("docker", "ps", "-a", "--filter", fmt.Sprintf("ancestor=%s", suite.imageName), "--format", "{{.ID}}")
	output, err := cmd.Output()
	if err != nil {
		suite.T().Logf("Warning: Failed to list containers for cleanup: %v", err)
		suite.cleanupFailed = true
		return
	}
	
	containerIDs := strings.Fields(strings.TrimSpace(string(output)))
	if len(containerIDs) == 0 {
		suite.T().Log("No orphaned containers found")
		return
	}
	
	suite.T().Logf("Found %d orphaned container(s), cleaning up...", len(containerIDs))
	
	// Stop all containers
	for _, containerID := range containerIDs {
		if containerID != suite.containerID { // Skip if it's the main container (already handled)
			suite.T().Logf("Stopping orphaned container %s...", containerID)
			if err := exec.Command("docker", "stop", containerID).Run(); err != nil {
				suite.T().Logf("Warning: Failed to stop orphaned container %s: %v", containerID, err)
				suite.cleanupFailed = true
			}
		}
	}
	
	// Remove all containers
	for _, containerID := range containerIDs {
		if containerID != suite.containerID { // Skip if it's the main container (already handled)
			suite.T().Logf("Removing orphaned container %s...", containerID)
			if err := exec.Command("docker", "rm", containerID).Run(); err != nil {
				suite.T().Logf("Warning: Failed to remove orphaned container %s: %v", containerID, err)
				suite.cleanupFailed = true
			}
		}
	}
}

// removeTestImage removes the Docker image created for testing
func (suite *E2ETestSuite) removeTestImage() {
	if suite.imageName == "" {
		return
	}
	
	suite.T().Logf("Removing test image %s...", suite.imageName)
	
	// Check if image exists first
	cmd := exec.Command("docker", "images", "-q", suite.imageName)
	output, err := cmd.Output()
	if err != nil {
		suite.T().Logf("Warning: Failed to check if image exists: %v", err)
		suite.cleanupFailed = true
		return
	}
	
	if strings.TrimSpace(string(output)) == "" {
		suite.T().Log("Test image not found, skipping removal")
		return
	}
	
	// Remove the image
	if err := exec.Command("docker", "rmi", suite.imageName).Run(); err != nil {
		suite.T().Logf("Warning: Failed to remove test image %s: %v", suite.imageName, err)
		suite.cleanupFailed = true
	} else {
		suite.T().Logf("Successfully removed test image %s", suite.imageName)
	}
}

// cleanupDanglingArtifacts removes dangling images and build cache
func (suite *E2ETestSuite) cleanupDanglingArtifacts() {
	suite.T().Log("Cleaning up dangling Docker artifacts...")
	
	// Remove dangling images
	cmd := exec.Command("docker", "image", "prune", "-f")
	if err := cmd.Run(); err != nil {
		suite.T().Logf("Warning: Failed to prune dangling images: %v", err)
		suite.cleanupFailed = true
	} else {
		suite.T().Log("Successfully pruned dangling images")
	}
	
	// Clean up build cache (only remove dangling cache, not all cache)
	cmd = exec.Command("docker", "builder", "prune", "-f")
	if err := cmd.Run(); err != nil {
		suite.T().Logf("Warning: Failed to prune build cache: %v", err)
		suite.cleanupFailed = true
	} else {
		suite.T().Log("Successfully pruned build cache")
	}
}

// setupSignalHandler sets up signal handling for graceful cleanup on interruption
func (suite *E2ETestSuite) setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-c
		suite.T().Log("\n🚨 Received interrupt signal, performing emergency cleanup...")
		suite.performComprehensiveCleanup()
		suite.T().Log("Emergency cleanup completed")
		os.Exit(1)
	}()
}

// verifyCleanupSuccess verifies that all Docker artifacts have been properly cleaned up
func (suite *E2ETestSuite) verifyCleanupSuccess() {
	suite.T().Log("Verifying cleanup success...")
	
	// Check if container still exists
	if suite.containerID != "" {
		cmd := exec.Command("docker", "ps", "-a", "-q", "--filter", fmt.Sprintf("id=%s", suite.containerID))
		output, err := cmd.Output()
		if err == nil && strings.TrimSpace(string(output)) != "" {
			suite.T().Logf("⚠️  Container %s still exists after cleanup", suite.containerID)
			suite.cleanupFailed = true
		}
	}
	
	// Check if test image still exists
	if suite.imageName != "" {
		cmd := exec.Command("docker", "images", "-q", suite.imageName)
		output, err := cmd.Output()
		if err == nil && strings.TrimSpace(string(output)) != "" {
			suite.T().Logf("⚠️  Test image %s still exists after cleanup", suite.imageName)
			suite.cleanupFailed = true
		}
	}
	
	if !suite.cleanupFailed {
		suite.T().Log("✅ Cleanup verification passed")
	}
}

// makeRequest makes an HTTP request to the containerized service
func (suite *E2ETestSuite) makeRequest(method, path string, payload interface{}) (*http.Response, []byte, error) {
	var body io.Reader
	if payload != nil {
		jsonData, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, err
		}
		body = bytes.NewBuffer(jsonData)
	}
	
	req, err := http.NewRequest(method, suite.baseURL+path, body)
	if err != nil {
		return nil, nil, err
	}
	
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	
	resp, err := suite.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	
	responseBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return resp, nil, err
	}
	
	return resp, responseBody, nil
}

// TestHealthEndpoints tests health check endpoints in containerized environment
func (suite *E2ETestSuite) TestHealthEndpoints() {
	endpoints := []string{"/health", "/health/live", "/health/ready"}
	
	for _, endpoint := range endpoints {
		suite.Run(endpoint, func() {
			resp, body, err := suite.makeRequest("GET", endpoint, nil)
			require.NoError(suite.T(), err)
			assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
			
			var response map[string]interface{}
			err = json.Unmarshal(body, &response)
			require.NoError(suite.T(), err)
			assert.Contains(suite.T(), response, "status")
		})
	}
}

// TestMetricsEndpoint tests Prometheus metrics endpoint
func (suite *E2ETestSuite) TestMetricsEndpoint() {
	resp, body, err := suite.makeRequest("GET", "/metrics", nil)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
	
	bodyStr := string(body)
	assert.Contains(suite.T(), bodyStr, "# HELP")
	assert.Contains(suite.T(), bodyStr, "# TYPE")
	
	// Check for some expected metrics
	expectedMetrics := []string{
		"http_requests_total",
		"http_request_duration_seconds",
	}
	
	for _, metric := range expectedMetrics {
		assert.Contains(suite.T(), bodyStr, metric, "Expected metric %s not found", metric)
	}
}

// TestCryptoEndpoints tests crypto operations end-to-end
func (suite *E2ETestSuite) TestCryptoEndpoints() {
	suite.Run("Hash operation", func() {
		payload := map[string]interface{}{
			"content":   "hello world",
			"algorithm": "sha256",
		}
		
		resp, body, err := suite.makeRequest("POST", "/api/v1/crypto/hash", payload)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var response apierror.SuccessResponse
		err = json.Unmarshal(body, &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)
		
		data := response.Data.(map[string]interface{})
		assert.Contains(suite.T(), data, "hash")
		assert.Contains(suite.T(), data, "algorithm")
		assert.Equal(suite.T(), "sha256", data["algorithm"])
		
		// Verify the hash is correct
		expectedHash := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
		assert.Equal(suite.T(), expectedHash, data["hash"])
	})
	
	suite.Run("Password hash and verify workflow", func() {
		// Hash a password
		hashPayload := map[string]interface{}{
			"password": "testpassword123",
		}
		
		resp, body, err := suite.makeRequest("POST", "/api/v1/crypto/password/hash", hashPayload)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var hashResponse apierror.SuccessResponse
		err = json.Unmarshal(body, &hashResponse)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), hashResponse.Success)
		
		hashData := hashResponse.Data.(map[string]interface{})
		hashedPassword := hashData["hash"].(string)
		assert.NotEmpty(suite.T(), hashedPassword)
		assert.Contains(suite.T(), hashedPassword, "$argon2id$")
		
		// Verify the password
		verifyPayload := map[string]interface{}{
			"password": "testpassword123",
			"hash":     hashedPassword,
		}
		
		resp, body, err = suite.makeRequest("POST", "/api/v1/crypto/password/verify", verifyPayload)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var verifyResponse apierror.SuccessResponse
		err = json.Unmarshal(body, &verifyResponse)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), verifyResponse.Success)
		
		verifyData := verifyResponse.Data.(map[string]interface{})
		assert.True(suite.T(), verifyData["valid"].(bool))
		
		// Verify with wrong password
		wrongVerifyPayload := map[string]interface{}{
			"password": "wrongpassword",
			"hash":     hashedPassword,
		}
		
		resp, body, err = suite.makeRequest("POST", "/api/v1/crypto/password/verify", wrongVerifyPayload)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		err = json.Unmarshal(body, &verifyResponse)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), verifyResponse.Success)
		
		verifyData = verifyResponse.Data.(map[string]interface{})
		assert.False(suite.T(), verifyData["valid"].(bool))
	})
	
	suite.Run("HMAC operation", func() {
		payload := map[string]interface{}{
			"content":   "hello world",
			"key":       "secret",
			"algorithm": "sha256",
		}
		
		resp, body, err := suite.makeRequest("POST", "/api/v1/crypto/hmac", payload)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var response apierror.SuccessResponse
		err = json.Unmarshal(body, &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)
		
		data := response.Data.(map[string]interface{})
		assert.Contains(suite.T(), data, "hmac")
		assert.Contains(suite.T(), data, "algorithm")
	})
}

// TestTextEndpoints tests text processing operations end-to-end
func (suite *E2ETestSuite) TestTextEndpoints() {
	suite.Run("Case conversion", func() {
		payload := map[string]interface{}{
			"content":  "hello world",
			"caseType": "UPPERCASE",
		}
		
		resp, body, err := suite.makeRequest("POST", "/api/v1/text/case", payload)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var response apierror.SuccessResponse
		err = json.Unmarshal(body, &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)
		
		data := response.Data.(map[string]interface{})
		assert.Equal(suite.T(), "HELLO WORLD", data["result"])
	})
	
	suite.Run("Text analysis", func() {
		payload := map[string]interface{}{
			"content": "Hello world!\nThis is a test.\nIt has multiple lines and sentences.",
		}
		
		resp, body, err := suite.makeRequest("POST", "/api/v1/text/info", payload)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var response apierror.SuccessResponse
		err = json.Unmarshal(body, &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)
		
		data := response.Data.(map[string]interface{})
		assert.Contains(suite.T(), data, "characterCount")
		assert.Contains(suite.T(), data, "wordCount")
		assert.Contains(suite.T(), data, "lineCount")
		assert.Contains(suite.T(), data, "sentenceCount")
		assert.Contains(suite.T(), data, "byteSize")
		
		// Verify some expected values
		assert.Equal(suite.T(), float64(3), data["lineCount"])
		assert.True(suite.T(), data["wordCount"].(float64) > 0)
		assert.True(suite.T(), data["sentenceCount"].(float64) >= 2)
	})
}

// TestTransformEndpoints tests transformation operations end-to-end
func (suite *E2ETestSuite) TestTransformEndpoints() {
	suite.Run("Base64 encode/decode workflow", func() {
		originalContent := "Hello, World! 🌍"
		
		// Encode
		encodePayload := map[string]interface{}{
			"content": originalContent,
			"action":  "encode",
		}
		
		resp, body, err := suite.makeRequest("POST", "/api/v1/transform/base64", encodePayload)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var encodeResponse apierror.SuccessResponse
		err = json.Unmarshal(body, &encodeResponse)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), encodeResponse.Success)
		
		encodeData := encodeResponse.Data.(map[string]interface{})
		encodedContent := encodeData["result"].(string)
		assert.NotEmpty(suite.T(), encodedContent)
		
		// Decode
		decodePayload := map[string]interface{}{
			"content": encodedContent,
			"action":  "decode",
		}
		
		resp, body, err = suite.makeRequest("POST", "/api/v1/transform/base64", decodePayload)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var decodeResponse apierror.SuccessResponse
		err = json.Unmarshal(body, &decodeResponse)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), decodeResponse.Success)
		
		decodeData := decodeResponse.Data.(map[string]interface{})
		decodedContent := decodeData["result"].(string)
		assert.Equal(suite.T(), originalContent, decodedContent)
	})
	
	suite.Run("JWT decoding", func() {
		// Use a sample JWT token
		sampleJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
		
		payload := map[string]interface{}{
			"token": sampleJWT,
		}
		
		resp, body, err := suite.makeRequest("POST", "/api/v1/transform/jwt/decode", payload)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var response apierror.SuccessResponse
		err = json.Unmarshal(body, &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)
		
		data := response.Data.(map[string]interface{})
		assert.Contains(suite.T(), data, "header")
		assert.Contains(suite.T(), data, "payload")
		assert.Contains(suite.T(), data, "signatureVerified")
		assert.False(suite.T(), data["signatureVerified"].(bool))
		
		// Verify header content
		header := data["header"].(map[string]interface{})
		assert.Equal(suite.T(), "HS256", header["alg"])
		assert.Equal(suite.T(), "JWT", header["typ"])
		
		// Verify payload content
		payload_data := data["payload"].(map[string]interface{})
		assert.Equal(suite.T(), "1234567890", payload_data["sub"])
		assert.Equal(suite.T(), "John Doe", payload_data["name"])
	})
}

// TestIDEndpoints tests ID generation operations end-to-end
func (suite *E2ETestSuite) TestIDEndpoints() {
	suite.Run("UUID generation", func() {
		payload := map[string]interface{}{
			"version": 4,
			"count":   3,
		}
		
		resp, body, err := suite.makeRequest("POST", "/api/v1/id/uuid", payload)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var response apierror.SuccessResponse
		err = json.Unmarshal(body, &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)
		
		data := response.Data.(map[string]interface{})
		uuids := data["uuids"].([]interface{})
		assert.Len(suite.T(), uuids, 3)
		
		for _, uuid := range uuids {
			uuidStr := uuid.(string)
			assert.Len(suite.T(), uuidStr, 36) // Standard UUID length
			assert.Contains(suite.T(), uuidStr, "-")
		}
	})
	
	suite.Run("Nano ID generation", func() {
		payload := map[string]interface{}{
			"size":  10,
			"count": 2,
		}
		
		resp, body, err := suite.makeRequest("POST", "/api/v1/id/nanoid", payload)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var response apierror.SuccessResponse
		err = json.Unmarshal(body, &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)
		
		data := response.Data.(map[string]interface{})
		ids := data["ids"].([]interface{})
		assert.Len(suite.T(), ids, 2)
		
		for _, id := range ids {
			idStr := id.(string)
			assert.Len(suite.T(), idStr, 10)
			// Nano IDs should be URL-safe
			assert.NotContains(suite.T(), idStr, " ")
			assert.NotContains(suite.T(), idStr, "+")
			assert.NotContains(suite.T(), idStr, "/")
		}
	})
}

// TestTimeEndpoints tests time utility operations end-to-end
func (suite *E2ETestSuite) TestTimeEndpoints() {
	suite.Run("Current time", func() {
		resp, body, err := suite.makeRequest("GET", "/api/v1/time/now", nil)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var response apierror.SuccessResponse
		err = json.Unmarshal(body, &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)
		
		data := response.Data.(map[string]interface{})
		expectedFields := []string{"unixSeconds", "unixMilliseconds", "iso8601", "rfc3339", "humanReadable"}
		for _, field := range expectedFields {
			assert.Contains(suite.T(), data, field)
		}
		
		// Verify the time is reasonable (within last minute)
		unixSeconds := int64(data["unixSeconds"].(float64))
		now := time.Now().Unix()
		assert.True(suite.T(), now-unixSeconds < 60, "Time should be current")
	})
}

// TestNetworkEndpoints tests network utility operations end-to-end
func (suite *E2ETestSuite) TestNetworkEndpoints() {
	suite.Run("URL parsing", func() {
		payload := map[string]interface{}{
			"url":    "https://example.com:8080/path?param=value&other=test#fragment",
			"action": "parse",
		}
		
		resp, body, err := suite.makeRequest("POST", "/api/v1/web/url", payload)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var response apierror.SuccessResponse
		err = json.Unmarshal(body, &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)
		
		data := response.Data.(map[string]interface{})
		assert.Equal(suite.T(), "https", data["scheme"])
		assert.Equal(suite.T(), "example.com:8080", data["host"])
		assert.Equal(suite.T(), "/path", data["path"])
		assert.Equal(suite.T(), "fragment", data["fragment"])
		
		query := data["query"].(map[string]interface{})
		assert.Equal(suite.T(), "value", query["param"])
		assert.Equal(suite.T(), "test", query["other"])
	})
	
	suite.Run("IP analysis", func() {
		testIPs := []struct {
			ip        string
			isPrivate bool
			isPublic  bool
			version   int
		}{
			{"8.8.8.8", false, true, 4},
			{"192.168.1.1", true, false, 4},
			{"127.0.0.1", false, false, 4},
		}
		
		for _, testIP := range testIPs {
			suite.Run(testIP.ip, func() {
				payload := map[string]interface{}{
					"ip": testIP.ip,
				}
				
				resp, body, err := suite.makeRequest("POST", "/api/v1/network/ip", payload)
				require.NoError(suite.T(), err)
				assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
				
				var response apierror.SuccessResponse
				err = json.Unmarshal(body, &response)
				require.NoError(suite.T(), err)
				assert.True(suite.T(), response.Success)
				
				data := response.Data.(map[string]interface{})
				assert.Equal(suite.T(), testIP.ip, data["ip"])
				assert.Equal(suite.T(), float64(testIP.version), data["version"])
				assert.Equal(suite.T(), testIP.isPrivate, data["isPrivate"])
				assert.Equal(suite.T(), testIP.isPublic, data["isPublic"])
			})
		}
	})
}

// TestErrorHandling tests error scenarios in containerized environment
func (suite *E2ETestSuite) TestErrorHandling() {
	suite.Run("404 Not Found", func() {
		resp, body, err := suite.makeRequest("GET", "/nonexistent", nil)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), http.StatusNotFound, resp.StatusCode)
		
		var response apierror.ErrorResponse
		err = json.Unmarshal(body, &response)
		require.NoError(suite.T(), err)
		assert.False(suite.T(), response.Success)
		assert.NotEmpty(suite.T(), response.Error.Code)
	})
	
	suite.Run("Invalid JSON", func() {
		req, _ := http.NewRequest("POST", suite.baseURL+"/api/v1/crypto/hash", 
			strings.NewReader("invalid json"))
		req.Header.Set("Content-Type", "application/json")
		
		resp, err := suite.httpClient.Do(req)
		require.NoError(suite.T(), err)
		defer resp.Body.Close()
		
		assert.Equal(suite.T(), http.StatusBadRequest, resp.StatusCode)
		
		body, err := io.ReadAll(resp.Body)
		require.NoError(suite.T(), err)
		
		var response apierror.ErrorResponse
		err = json.Unmarshal(body, &response)
		require.NoError(suite.T(), err)
		assert.False(suite.T(), response.Success)
	})
}

// TestContainerResourceUsage tests resource usage in containerized environment
func (suite *E2ETestSuite) TestContainerResourceUsage() {
	suite.Run("Memory usage", func() {
		// Get container stats
		cmd := exec.Command("docker", "stats", "--no-stream", "--format", 
			"table {{.MemUsage}}", suite.containerID)
		output, err := cmd.Output()
		if err != nil {
			suite.T().Skip("Could not get container stats")
		}
		
		suite.T().Logf("Container memory usage: %s", strings.TrimSpace(string(output)))
		
		// Perform some operations to test memory usage
		for i := 0; i < 100; i++ {
			payload := map[string]interface{}{
				"content":   fmt.Sprintf("test content %d", i),
				"algorithm": "sha256",
			}
			
			resp, _, err := suite.makeRequest("POST", "/api/v1/crypto/hash", payload)
			require.NoError(suite.T(), err)
			assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		}
		
		// Get stats after operations
		cmd = exec.Command("docker", "stats", "--no-stream", "--format", 
			"table {{.MemUsage}}", suite.containerID)
		output, err = cmd.Output()
		if err == nil {
			suite.T().Logf("Container memory usage after operations: %s", strings.TrimSpace(string(output)))
		}
	})
}

// Run the E2E test suite
func TestE2ESuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E tests in short mode")
	}
	
	// Check if we should skip Docker tests
	if os.Getenv("SKIP_DOCKER_TESTS") == "true" {
		t.Skip("Skipping Docker E2E tests (SKIP_DOCKER_TESTS=true)")
	}
	
	suite.Run(t, new(E2ETestSuite))
}