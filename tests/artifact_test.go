package tests

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Velocidex/ordereddict"
	"github.com/alecthomas/assert"
	"github.com/bodgit/sevenzip"
	"github.com/sebdah/goldie/v2"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	reghiveTestDirectory = "./test_files/C/"

	// Use this for now until the next official release
	velociraptorBinaryURL  = "https://github.com/Velocidex/velociraptor/releases/download/v0.74/velociraptor-v0.74.3-linux-amd64-musl"
	velociraptorBinaryPath = "./velociraptor"

	// The produced artifact
	artifactPath = "../output/Windows.Registry.Hunter.yaml"
)

type downloadSpec struct {
	archive string
	prefix  string
	url     string
}

var (
	// Detect when the log has failed.
	logHasFailed = regexp.MustCompile("(parse_binary: Field filename Expecting a path arg type|types.Null)")

	downloadSpecs = []downloadSpec{
		// Most of the system hives are here
		{
			archive: "./archives/APTSimulatorVM_RegistryHives_Server2022.7z",
			prefix:  "/windows/system32/",
			url:     "https://github.com/AndrewRathbun/DFIRArtifactMuseum/raw/main/Windows/Registry/Server2022/APTSimulatorVM/APTSimulatorVM_RegistryHives_Server2022.7z",
		},

		// User hives are here
		{
			archive: "./archives/EZ_W7RegistryHives.7z",
			prefix:  "/Users/user1/",
			url:     "https://github.com/AndrewRathbun/DFIRArtifactMuseum/raw/main/Windows/Registry/Win7/EricZimmerman/EZ_W7RegistryHives.7z",
		},
	}
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

func (self *RegistryHunterTestSuite) extractFile(
	file *sevenzip.File, base_path string) error {
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

	err := self.fetchFile(velociraptorBinaryURL, velociraptorBinaryPath)
	assert.NoError(self.T(), err)

	// Ensure the file is executable
	os.Chmod(velociraptorBinaryPath, 0700)
	self.binary = velociraptorBinaryPath

	_, err = os.Lstat(reghiveTestDirectory)
	if err != nil && !os.IsExist(err) {
		for _, d := range downloadSpecs {
			err := self.fetchFile(d.url, d.archive)
			assert.NoError(self.T(), err)

			r, err := sevenzip.OpenReader(d.archive)
			assert.NoError(self.T(), err)
			defer r.Close()

			for _, file := range r.File {
				os.MkdirAll(reghiveTestDirectory+d.prefix, 0700)
				err = self.extractFile(file, reghiveTestDirectory+d.prefix)
				assert.NoError(self.T(), err)
			}
		}
	}

	// Make sure env config does not interfere with this test
	os.Setenv("VELOCIRAPTOR_CONFIG", "")
}

type testCase struct {
	Name       string
	Artifact   string
	RuleFilter string
	Root       string
	Columns    []string

	Disable bool
}

var (
	standardColumns = []string{
		"Description", "Category", "OSPath", "Mtime", "Details",
	}

	testCases = []testCase{
		// Cover off on all the different hives we are supposed to map
		{
			// Covers HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services
			Name:       "Interface Properties",
			Artifact:   "Windows.Registry.Hunter/Results",
			RuleFilter: "Interface Properties",
			Root:       reghiveTestDirectory,
			Columns:    standardColumns,
		},
		{
			// Covers HKEY_LOCAL_MACHINE\Software
			Name:       "WinLogon",
			Artifact:   "Windows.Registry.Hunter/Results",
			RuleFilter: "WinLogon: Displays the details of the last user",
			Root:       reghiveTestDirectory,
			Columns:    standardColumns,
		},
		{
			// Covers HKEY_LOCAL_MACHINE\System
			Name:       "System Info",
			Artifact:   "Windows.Registry.Hunter/Results",
			RuleFilter: "System Info",
			Root:       reghiveTestDirectory,
			Columns:    standardColumns,
		},
		{
			// Covers HKEY_LOCAL_MACHINE\System
			Name:       "Firewall Rules",
			Artifact:   "Windows.Registry.Hunter/Results",
			RuleFilter: "Firewall Rules",
			Root:       reghiveTestDirectory,
			Columns:    standardColumns,
		},
		{
			// Covers HKEY_USERS
			Name:       "Regedit.exe",
			Artifact:   "Windows.Registry.Hunter/Results",
			RuleFilter: "Regedit.exe",
			Root:       reghiveTestDirectory,
			Columns:    standardColumns,
		},
		{
			// Covers HKEY_USERS
			Name:       "MRU",
			Artifact:   "Windows.Registry.Hunter/Results",
			RuleFilter: "MRU",
			Root:       reghiveTestDirectory,
			Columns:    standardColumns,
		},
		{
			// Covers HKEY_USERS
			Name:       "UserAssist",
			Artifact:   "Windows.Registry.Hunter/Results",
			RuleFilter: "UserAssist",
			Root:       reghiveTestDirectory,
			Columns:    standardColumns,
		},
		{
			// Covers HKEY_USERS
			Name:       "WordWheelQuery",
			Artifact:   "Windows.Registry.Hunter/Results",
			RuleFilter: "WordWheelQuery",
			Root:       reghiveTestDirectory,
			Columns:    standardColumns,
		},
		{
			// Covers HKEY_LOCAL_MACHINE\System
			Name:       "Background Activity Moderator",
			Artifact:   "Windows.Registry.Hunter/Results",
			RuleFilter: "Background Activity Moderator",
			Root:       reghiveTestDirectory,
			Columns:    standardColumns,
		},
		{
			Name:       "UserAssist",
			Artifact:   "Windows.Registry.Hunter/Results",
			RuleFilter: "UserAssist",
			Root:       reghiveTestDirectory,
			Columns:    standardColumns,
		},
		{
			Name:       "Recent File List",
			Artifact:   "Windows.Registry.Hunter/Results",
			RuleFilter: "Recent File List",
			Root:       reghiveTestDirectory,
			Columns:    standardColumns,
		},
		{
			Name:       "User Shell Folders",
			Artifact:   "Windows.Registry.Hunter/Results",
			RuleFilter: "User Shell Folders",
			Root:       reghiveTestDirectory,
			Columns:    standardColumns,
		},
		{
			Name:       "RDP",
			Artifact:   "Windows.Registry.Hunter/Results",
			RuleFilter: "RDP",
			Root:       reghiveTestDirectory,
			Columns:    standardColumns,
		},
		{
			Name:       "Scheduled Tasks",
			Artifact:   "Windows.Registry.Hunter/Results",
			RuleFilter: "Scheduled Tasks",
			Root:       reghiveTestDirectory,
			Columns:    standardColumns,
		},
		{
			Name:       "Services",
			Artifact:   "Windows.Registry.Hunter/Results",
			RuleFilter: "Services",
			Root:       reghiveTestDirectory,
			Columns:    standardColumns,
		},
		{
			Name:       "Environment",
			Artifact:   "Windows.Registry.Hunter/Results",
			RuleFilter: "Environment",
			Root:       reghiveTestDirectory,
			Columns:    standardColumns,
		},
	}
)

func (self *RegistryHunterTestSuite) TestArtifact() {
	log_file, err := ioutil.TempFile("", "reghunter_test")
	assert.NoError(self.T(), err)
	log_file.Close()

	defer os.Remove(log_file.Name())

	// First check that we actually can load the artifact - this checks for syntax errors.
	cmd := exec.Command(self.binary, "-v", "--definitions", artifactPath,
		"--logfile", log_file.Name(),
		"artifacts", "list", "Windows.Registry.Hunter")
	out, err := cmd.CombinedOutput()
	require.NoError(self.T(), err, string(out))

	for _, test := range testCases {
		if test.Disable {
			continue
		}

		RootDrive, _ := filepath.Abs(test.Root)
		cmdline := []string{
			self.binary, "--logfile", log_file.Name(),
			"--definitions", artifactPath, "--debug", "--debug_port", "6061",
			"artifacts", "collect", test.Artifact, "--format", "jsonl",
			"--args", "RootDrive=" + RootDrive,
			"--args", `RemappingStrategy=Raw Hives`,
			"--args", "RuleFilter=" + test.RuleFilter,
		}
		fmt.Printf("Testing %v\nRunning command %v\n", test.Name, cmdline)

		cmd := exec.Command(self.binary, cmdline[1:]...)
		out, err := cmd.CombinedOutput()
		require.NoError(self.T(), err, string(out))

		log_message := asJsonL(selectColumns(
			extractLogMessagesFromFile(log_file.Name()), []string{"level", "msg"}))
		fmt.Println(log_message)
		if logHasFailed.MatchString(log_message) {
			self.T().Fatalf("Log contains errors: %v", log_message)
		}

		results := sortRows(selectColumns(
			extractLogMessages(string(out)), test.Columns))

		g := goldie.New(self.T(),
			goldie.WithFixtureDir("fixtures"),
			goldie.WithNameSuffix(".golden"),
			goldie.WithDiffEngine(goldie.ColoredDiff),
		)

		g.AssertJson(self.T(), test.Name, results)
	}
}

func asJson(rows []*ordereddict.Dict) string {
	serialized, _ := json.MarshalIndent(rows, "", "  ")
	return string(serialized)
}

func asJsonL(rows []*ordereddict.Dict) string {
	res := ""
	for _, r := range rows {
		res += r.String() + "\n"
	}

	return res
}

// Sort the rows to make them stable
func sortRows(rows []*ordereddict.Dict) []*ordereddict.Dict {
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].String() < rows[j].String()
	})

	return rows
}

func selectColumns(rows []*ordereddict.Dict, columns []string) []*ordereddict.Dict {
	res := []*ordereddict.Dict{}
	for _, item := range rows {
		row := ordereddict.NewDict()
		for _, c := range columns {
			v, pres := item.Get(c)
			if pres {
				row.Set(c, v)
			}
		}
		if len(row.Keys()) > 0 {
			res = append(res, row)
		}
	}
	return res
}

func extractLogMessagesFromFile(filename string) []*ordereddict.Dict {
	fd, err := os.Open(filename)
	if err != nil {
		return []*ordereddict.Dict{ordereddict.NewDict().Set("Error", err.Error())}
	}
	defer fd.Close()

	data, err := ioutil.ReadAll(fd)
	if err != nil {
		return []*ordereddict.Dict{ordereddict.NewDict().Set("Error", err.Error())}
	}

	return extractLogMessages(string(data))
}

func extractLogMessages(data string) (result []*ordereddict.Dict) {

	reader := bufio.NewReader(strings.NewReader(data))
	for {
		row_data, _ := reader.ReadBytes('\n')
		if len(row_data) == 0 {
			break
		}

		// Empty line
		if len(row_data) == 1 {
			continue
		}

		item_dict := ordereddict.NewDict()
		err := item_dict.UnmarshalJSON(row_data)
		if err != nil {
			continue
		}

		result = append(result, item_dict)
	}

	return result
}

func TestRegistryHunter(t *testing.T) {
	suite.Run(t, &RegistryHunterTestSuite{})
}
