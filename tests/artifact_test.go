package tests

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alecthomas/assert"
	"github.com/bodgit/sevenzip"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	reghiveArchive       = "./archives/APTSimulatorVM_RegistryHives_Server2022.7z"
	reghiveTestDirectory = "./test_files/APTSimulatorVM_RegistryHives_Server2022/"
	reghiveURL           = "https://github.com/AndrewRathbun/DFIRArtifactMuseum/raw/main/Windows/Registry/Server2022/APTSimulatorVM/APTSimulatorVM_RegistryHives_Server2022.7z"

	// Use this for now until the next official release
	velociraptorBinaryURL  = "https://storage.googleapis.com/releases.velocidex.com/velociraptor/velociraptor-v0.72-rc1-linux-amd64-musl"
	velociraptorBinaryPath = "./velociraptor"

	// The produced artifact
	artifactPath = "../output/Windows.Registry.Hunter.yaml"
)

type RegistryHunterTestSuite struct {
	suite.Suite

	binary string
}

func (self *RegistryHunterTestSuite) fetchFile(url, dest string) error {
	_, err := os.Lstat(dest)
	if err == nil || os.IsExist(err) {
		return nil
	}

	out, err := os.OpenFile(dest,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out.Close()

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	fmt.Printf("Fetching url %v\n", url)

	_, err = io.Copy(out, resp.Body)
	return err
}

func (self *RegistryHunterTestSuite) extractFile(file *sevenzip.File, base_path string) error {
	dest := filepath.Join(base_path, file.Name)

	// Ensure the directory exists
	if strings.HasSuffix(file.Name, "/") {
		os.MkdirAll(dest, 0700)
		return nil
	}

	infd, err := file.Open()
	if err != nil {
		return err
	}
	defer infd.Close()

	out, err := os.OpenFile(dest,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out.Close()

	fmt.Printf("Extracting %v\n", dest)

	_, err = io.Copy(out, infd)
	return err
}

func (self *RegistryHunterTestSuite) SetupTest() {
	err := self.fetchFile(reghiveURL, reghiveArchive)
	assert.NoError(self.T(), err)

	err = self.fetchFile(velociraptorBinaryURL, velociraptorBinaryPath)
	assert.NoError(self.T(), err)

	// Ensure the file is executable
	os.Chmod(velociraptorBinaryPath, 0700)
	self.binary = velociraptorBinaryPath

	_, err = os.Lstat(reghiveTestDirectory)
	if err != nil && !os.IsExist(err) {
		r, err := sevenzip.OpenReader(reghiveArchive)
		assert.NoError(self.T(), err)
		defer r.Close()

		for _, file := range r.File {
			err = self.extractFile(file, reghiveTestDirectory)
			assert.NoError(self.T(), err)
		}
	}

	// Make sure env config does not interfere with this test
	os.Setenv("VELOCIRAPTOR_CONFIG", "")
}

func (self *RegistryHunterTestSuite) TestArtifact() {
	cmd := exec.Command(self.binary, "-v", "--definitions", artifactPath,
		"artifacts", "list", "Windows.Registry.Hunter")
	out, err := cmd.CombinedOutput()
	require.NoError(self.T(), err, string(out))

	fmt.Println(string(out))
}

func TestRegistryHunter(t *testing.T) {
	suite.Run(t, &RegistryHunterTestSuite{})
}
