package compiler

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/Velocidex/ordereddict"
	"github.com/Velocidex/registry_hunter/config"
	"github.com/Velocidex/yaml/v2"
)

var (
	// The following roots refer to the virtual hives that are mounted
	// on the remap config. Rules may not specific different roots
	// from these.
	allowedRoots = []string{
		// Rules that do not glob can have an empty root glob.
		"",
		"/",
		"Amcache",
		"HKEY_USERS",
		"SAM",
		"HKEY_LOCAL_MACHINE\\Security",
		"HKEY_LOCAL_MACHINE\\System",
		"HKEY_LOCAL_MACHINE\\Software",
	}
)

const (
	artifact_template = `
name: {{.Name}}
description: |
   This artifact parses and categorizes information for the registry.

   Build time: {{ .Time }}

   Read more about this artifact here https://github.com/Velocidex/registry_hunter

   ## RemappingStrategy

   In order to present a unified view of all registry hives we remap various
   hives we remap various hives into the "registry" accessor. There are a
   number of strategies implemented for this:

   1. API - This strategy uses the API for the majority of hives including
      user hives. Therefore users who are not currently logged in will not
      have their NTUser.dat hives mounted.
   2. API And NTUser.dat - This strategy uses the API for most of the hives,
      except for all the raw user hives will be mapped in HKEY_USERS.
      Therefore all users will be visible.
   3. Raw Hives - This stragegy is most suitable for working off an image or
       acquired hive files. All raw hives will be mapped (include SYSTEM, SOFTWARE etc).

   Using the API will result in faster collection times, but may be some
   differences:

   * Some registry keys are blocked with API access, even for the system
     user - so we get permission denied for these. Therefore, even with the API
     stragegy above we remap the raw files into the "raw_registry" accessor.
     The rule may work around this by using this accessor directly.
   * Some hive files are not accessible and can only be accessible using the
     API (e.g. the BCD hives).

parameters:
- name: Categories
  type: multichoice
  default: |
   {{ .CategoriesJSON }}
  choices:
   {{- range $val := .Categories }}
    - "{{ $val }}"
   {{- end }}
- name: CategoryFilter
  description: If this is set we use the regular expression instead of the choices above.
  type: regex
- name: CategoryExcludedFilter
  description: Exclude any categories based on this regular expression
  type: regex
  default: XXXXXX
- name: DescriptionFilter
  type: regex
  default: .
- name: RootFilter
  type: regex
  default: .
- name: RemappingStrategy
  description: |
     In order to present a unified view of all registry hives we remap various hives
     into the "registry" accessor. This setting controls the strategy we use to do so.
     See more information in the artifact description.
  type: choices
  default: "API And NTUser.dat"
  choices:
   - API
   - API And NTUser.dat
   - Raw Hives

- name: RootDrive
  default: C:/
  description: |
     Path to the top level drive. If one of the PathTO* parameters are not
     specified, then we use this to figure out the usual paths to the hives.

- name: AlsoUploadHives
  type: bool
  description: If checked, we also upload all the hives.

- name: PathTOSAM
  description: "By default, hive is at C:/Windows/System32/Config/SAM"

- name: PathTOAmcache
  description: "By default, hive is at C:/Windows/appcompat/Programs/Amcache.hve"

- name: PathTOSecurity
  description: "By default, hive is at C:/Windows/System32/Config/SECURITY"

- name: PathTOSystem
  description: "By default, hive is at C:/Windows/System32/Config/SYSTEM"

- name: PathTOSoftware
  description: "By default, hive is at C:/Windows/System32/Config/SOFTWARE"

- name: PathTOUsers
  description: "By default, directory is at C:/Users"

- name: NTFS_CACHE_TIME
  type: int
  description: How often to flush the NTFS cache. (Default is never).
  default: "1000000"

- name: DEBUG
  type: bool
  description: Add more logging.

export: |
    LET _info <= SELECT * FROM info()

    -- On Non Windows systems we need to use case insensitive accessor or we might not find the right hives.
    LET DefaultAccessor <= if(condition=_info[0].OS =~ "windows", then="ntfs", else="file_nocase")
    LET HKLM <= pathspec(parse="HKEY_LOCAL_MACHINE", path_type="registry")
    LET RootDrive <= pathspec(Path=RootDrive)
    LET PathTOSAM <= PathTOSAM || RootDrive + "Windows/System32/config/SAM"
    LET PathTOAmcache <= PathTOAmcache || RootDrive + "Windows/appcompat/Programs/Amcache.hve"
    LET PathTOSystem <= PathTOSystem || RootDrive + "Windows/System32/Config/System"
    LET PathTOSecurity <= PathTOSecurity || RootDrive + "Windows/System32/Config/Security"
    LET PathTOSoftware <= PathTOSoftware || RootDrive + "Windows/System32/Config/Software"
    LET PathTOUsers <= PathTOUsers || RootDrive + "Users/"

    -- HivePath: The path to the hive on disk
    -- RegistryPath: The path in the registry to mount the hive
    -- RegMountPoint: The path inside the hive to mount (usually /)
    LET _map_file_to_reg_path(HivePath, RegistryPath, RegMountPoint, Accessor, Description) = dict(
       type="mount", description=Description,
       ` + "`" + `from` + "`" + `=dict(accessor='raw_reg',
                   prefix=pathspec(
                      Path=RegMountPoint,
                      DelegateAccessor=Accessor,
                      DelegatePath=HivePath),
                   path_type='registry'),
        ` + "`" + `on` + "`" + `=dict(accessor='registry',
                  prefix=RegistryPath,
                  path_type='registry'))

    LET _standard_mappings = (
       _map_file_to_reg_path(
          HivePath=PathTOSystem,
          RegistryPath="HKEY_LOCAL_MACHINE\\System\\CurrentControlSet",
          RegMountPoint="/ControlSet001",
          Accessor=DefaultAccessor,
          Description="Map SYSTEM Hive to CurrentControlSet"),
       _map_file_to_reg_path(
          HivePath=PathTOSoftware,
          RegistryPath="HKEY_LOCAL_MACHINE\\Software",
          RegMountPoint="/",
          Accessor=DefaultAccessor,
          Description="Map Software hive to HKEY_LOCAL_MACHINE"),
       _map_file_to_reg_path(
          HivePath=PathTOSystem,
          RegistryPath="HKEY_LOCAL_MACHINE\\System",
          RegMountPoint="/",
          Accessor=DefaultAccessor,
          Description="Map System hive to HKEY_LOCAL_MACHINE"),
       _map_file_to_reg_path(
          HivePath=PathTOSecurity,
          RegistryPath="HKEY_LOCAL_MACHINE\\Security",
          RegMountPoint="/",
          Accessor=DefaultAccessor,
          Description="Map SECURITY Hive to HKEY_LOCAL_MACHINE"),
    )

    // Map raw hives for hives that are not normally accessible via API
    LET _unmounted_hive_mapping = (
      _map_file_to_reg_path(
          HivePath=PathTOSAM,
          RegistryPath="SAM",
          RegMountPoint="/",
          Accessor=DefaultAccessor,
          Description="Map SAM to /SAM/"),
      _map_file_to_reg_path(
          HivePath=PathTOAmcache,
          RegistryPath="Amcache",
          RegMountPoint="/",
          Accessor=DefaultAccessor,
          Description="Map Amcache to /Amcache/"),
    )

    LET _api_remapping <= (
        -- By default remap the entire "registry" accessor for API access.
        dict(type="mount",
          ` + "`" + `from` + "`" + `=dict(accessor="registry", prefix='/', path_type='registry'),
          on=dict(accessor="registry", prefix='/', path_type="registry")),

       -- Always remap raw Security because the API stops us from reading the keys.
       _map_file_to_reg_path(
          HivePath=PathTOSecurity,
          RegistryPath="HKEY_LOCAL_MACHINE\\Security",
          RegMountPoint="/",
          Accessor=DefaultAccessor,
          Description="Map SECURITY Hive to HKEY_LOCAL_MACHINE"),
    )

    -- In API mode we sometimes can not access the keys due to permissions.
    -- These mapping ensure rules can specifically access the raw hives if they
    -- need to.
    LET _raw_hive_mapping_for_api <= (
      dict(type="mount",
        description="Map System Hive to raw_registry accessor",
        ` + "`" + `from` + "`" + `=dict(accessor="raw_reg",
         prefix=pathspec(Path='/',
           DelegatePath=PathTOSystem,
           DelegateAccessor=DefaultAccessor),
         path_type='registry'),
       on=dict(accessor="raw_registry",
               prefix='/HKEY_LOCAL_MACHINE/System',
               path_type="registry")),
      dict(type="mount",
        description="Map Software Hive to raw_registry accessor",
        ` + "`" + `from` + "`" + `=dict(accessor="raw_reg",
         prefix=pathspec(Path='/',
           DelegatePath=PathTOSoftware,
           DelegateAccessor=DefaultAccessor),
         path_type='registry'),
       on=dict(accessor="raw_registry",
               prefix='/HKEY_LOCAL_MACHINE/Software',
               path_type="registry")),
    )

    // The BCD hive is normally located on an unmounted drive so we
    // always map it with the API.
    LET _bcd_map <= (dict(
       type="mount",
       ` + "`" + `from` + "`" + `=dict(accessor="registry", prefix='HKEY_LOCAL_MACHINE\\BCD00000000', path_type='registry'),
       on=dict(accessor="registry", prefix='HKEY_LOCAL_MACHINE\\BCD00000000', path_type="registry")))

    -- Map all the NTUser.dat files even in API mode because these are often not mounted.
    LET _map_ntuser = SELECT
    _map_file_to_reg_path(
      HivePath=OSPath,
      RegMountPoint="/",
      Accessor=DefaultAccessor,
      Description=format(format="Map NTUser.dat from User %v to HKEY_USERS",
                         args=OSPath[-2]),

      -- This is technically the SID but it is clearer to just use the username
      RegistryPath="HKEY_USERS\\" + OSPath[-2]) AS Mapping
    FROM glob(globs="*/NTUser.dat", root=PathTOUsers)

    LET _log_array(Message) = if(condition=log(message=Message), then=[])

    // Apply the mappings:
    LET RemapRules = if(condition=RemappingStrategy = "API",
       then=_api_remapping +
            _unmounted_hive_mapping +
            _raw_hive_mapping_for_api + _log_array(Message="Using API Mapping"),

    else=if(condition=RemappingStrategy = "API And NTUser.dat",
       then=_api_remapping +
            _map_ntuser.Mapping +
            _unmounted_hive_mapping +
            _raw_hive_mapping_for_api  +
            _log_array(Message="Using API And NTUser.dat Mapping"),

    else=_map_ntuser.Mapping +
         _unmounted_hive_mapping +
         _standard_mappings +
         _raw_hive_mapping_for_api +
         _log_array(Message="Using Raw Hives Mapping")))

{{ .Preamble }}

    -- This contains the queries for Full Query Rules - they skip the glob and just run arbitrary VQL.
    LET FullQueries <= parse_json_array(data=gunzip(string=base64decode(string="{{ .QueriesJSON }}")))

    LET AllFullQueries <=
        SELECT * FROM FullQueries
        WHERE Category =~ CategoryFilter
          AND Description =~ DescriptionFilter

    -- This contains the metadata for Glob rules.
    LET _MD <= parse_json_array(data=gunzip(string=base64decode(string="{{.Metadata }}")))
    LET MD(DescriptionFilter, RootFilter, CategoryFilter, CategoryExcludedFilter) =
     SELECT Glob, Category, Description,
            get(field="Details") AS Details,
            get(field="Comment") AS Comment,
            get(field="Filter") AS Filter, Root
     FROM _MD
     WHERE Description =~ DescriptionFilter
       AND Root =~ RootFilter
       AND Category =~ CategoryFilter
       AND NOT Category =~ CategoryExcludedFilter

    LET AllRules <=
      SELECT * FROM MD(DescriptionFilter=DescriptionFilter, RootFilter=RootFilter,
        CategoryFilter=CategoryFilter, CategoryExcludedFilter=CategoryExcludedFilter)

    LET AllGlobs <=
      SELECT Root, enumerate(items=Glob) AS Globs
      FROM AllRules
      GROUP BY Root

sources:
- name: Remapping
  query: |
    SELECT * FROM RemapRules

  notebook:
  - type: none

- name: Rules
  query: |
    SELECT * FROM chain(a=AllRules, b=AllFullQueries)
  notebook:
  - type: none

- name: Globs
  notebook:
  - type: none

  query: |
    SELECT * FROM AllGlobs

- name: Uploads
  notebook:
  - type: none

  query: |
   LET UploadFiles = SELECT OSPath AS SourceFile, Size,
       Btime AS Created,
       Ctime AS Changed,
       Mtime AS Modified,
       Atime AS LastAccessed,
       upload(file=OSPath, accessor=DefaultAccessor, mtime=Mtime) AS Upload
    FROM glob(accessor=DefaultAccessor, globs=[
       PathTOSAM, PathTOAmcache, PathTOSystem,
       PathTOSecurity, PathTOSoftware, PathTOUsers + "*/ntuser.dat*"
    ])

   SELECT * FROM if(condition=AlsoUploadHives, then=UploadFiles)

- name: Results
  notebook:
    - type: vql
      output: "<h1>All Results</h1>Press recalculate to View"
      template: |
         SELECT * FROM source(source="Results")

   {{- range $val := .Categories }}
    - type: vql
      output: "<h1>Category {{ $val }}</h1>Press recalculate to View"
      template: |
         /*
         # Category {{ $val }}
         */

         -- Adjust the Description Regex to focus on specific rules.
         SELECT Description, count() AS Count,
                OSPath AS Key, Mtime, Details FROM source()
         WHERE Category = '''{{ $val }}''' AND Description =~ "."
         GROUP BY Description

   {{- end }}
  query: |
    LET GlobsMD <= to_dict(item={
      SELECT Root AS _key, Globs AS _value FROM AllGlobs
    })

    LET ShouldLog <= NOT DEBUG

    LET Cache <= memoize(query={
       SELECT Glob, Category, Description,
              Details, Filter, Comment
       FROM AllRules
       WHERE ShouldLog || log(
           message="Add to cache %v %v", args=[Glob, Description], dedup=-1)
    }, key="Glob", period=100000)

    LET _ <= remap(config=dict(remappings=RemapRules))

    LET Result = SELECT OSPath, Mtime,
       Data.value AS Data,
       get(item=Cache, field=Globs[0]) AS Metadata,
       Globs[0] AS _Glob,
       IsDir
    FROM foreach(row={
       SELECT _key AS Root, _value AS GlobsToSearch
       FROM items(item=GlobsMD)
       WHERE Root =~ RootFilter
         AND log(message="Will search with globs %v at Root point %v",
             dedup=-1, args=[GlobsToSearch, Root])

    }, query={
       SELECT * FROM glob(globs=GlobsToSearch, root=Root, accessor="registry")
    })
    WHERE ShouldLog || log(
          message="Glob %v OSPath %v Metadata %v",
          args=[Globs[0], OSPath, Metadata], dedup=-1)

    LET GlobRules = SELECT Metadata.Description AS Description,
           Metadata.Category AS Category,
           OSPath, Mtime, Data AS _RawData,
           eval(func=Metadata.Details || "x=>x.Data") || Data AS Details,
           Metadata AS _Metadata
    FROM Result
    WHERE eval(func=Metadata.Filter || "x=>NOT IsDir")

    SELECT * FROM chain(
    a=GlobRules,
    b={
      SELECT * FROM foreach(row=AllFullQueries, query={
        SELECT * FROM query(query=Query, inherit=TRUE)
      })
    })
`
)

type templateParameters struct {
	Name     string
	Metadata string
	Rules    []config.RegistryRule
	Preamble string

	// Rules that are full queries
	QueriesJSON string

	Categories     []string
	CategoriesJSON string

	Time string
}

type Compiler struct {
	rules []config.RegistryRule
	md    map[string]config.RegistryRule

	// Detect rules using the same globs - these are not supported and
	// one of the rules will be rejected
	globs map[string]config.RegistryRule

	PreambleVerses []string

	categories map[string]bool

	queries []config.RegistryRule
}

func NewCompiler() *Compiler {
	return &Compiler{
		md:         make(map[string]config.RegistryRule),
		globs:      make(map[string]config.RegistryRule),
		categories: make(map[string]bool),
	}
}

func (self *Compiler) serialize(item interface{}) string {
	serialized, err := json.Marshal(item)
	if err != nil {
		return ""
	}
	return string(serialized)
}

var (
	pathSepRegex = regexp.MustCompile(`[/\\]+`)
)

func (self *Compiler) normalizeRoot(description, root string) string {
	for _, allowed := range allowedRoots {
		if strings.EqualFold(allowed, root) {
			return allowed
		}
	}

	fmt.Printf("Warning: Rule %v uses an unsupported Root: %v\n",
		description, root)
	return root
}

// FIXME: Currentl we duplicate the rules because each rule can only
// have one glob but it would be ideal if the same rule could have
// multiple globs.
func (self *Compiler) normalizeRule(r *config.RegistryRule) []config.RegistryRule {
	r.Glob = strings.TrimPrefix(pathSepRegex.ReplaceAllString(r.Glob, "\\"), "\\")
	r.Root = self.normalizeRoot(r.Description,
		pathSepRegex.ReplaceAllString(r.Root, "\\"))

	// Expand the glob expression to support brace expansions
	globs := []string{}
	_brace_expansion(r.Glob, &globs)

	res := []config.RegistryRule{}
	for _, glob := range globs {
		rule_copy := *r
		rule_copy.Glob = glob
		res = append(res, rule_copy)
	}
	return res
}

func (self *Compiler) LoadRules(filename string) error {
	fd, err := os.Open(filename)
	if err != nil {
		return err
	}

	data, err := ioutil.ReadAll(fd)
	if err != nil {
		return err
	}

	rules := &config.RuleFile{}
	err = yaml.UnmarshalStrict(data, rules)
	if err != nil {
		return err
	}

	fmt.Printf("Loading %v rules from %v\n", len(rules.Rules), filename)

	// Add preables from rules
	for _, r := range rules.Rules {
		for _, r := range self.normalizeRule(&r) {

			if r.Query != "" {
				self.queries = append(self.queries, r)
				continue
			}

			key := r.Root + r.Glob
			existing_rule, pres := self.globs[key]
			if pres {
				fmt.Printf("Rule %v by %v has the same glob (%v) as rule %v by %v... skipping this rule!\n",
					r.Description, r.Author, r.Glob,
					existing_rule.Description, existing_rule.Author)
			}
			self.globs[key] = r

			if len(r.Preamble) > 0 {
				self.PreambleVerses = append(self.PreambleVerses, r.Preamble...)
			}
			self.categories[r.Category] = true
			self.rules = append(self.rules, r)
		}
	}

	// Add global preambles
	self.PreambleVerses = append(self.PreambleVerses, rules.Preamble...)
	return nil
}

func (self *Compiler) buildMetadata() string {
	serialized, _ := json.Marshal(self.rules)

	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	gz.Write(serialized)
	gz.Close()
	return base64.StdEncoding.EncodeToString(b.Bytes())
}

func (self *Compiler) compress(in string) string {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	gz.Write([]byte(in))
	gz.Close()
	return base64.StdEncoding.EncodeToString(b.Bytes())
}

func (self *Compiler) buildPreamble() string {
	preamble := ordereddict.NewDict()

	for _, p := range self.PreambleVerses {
		if p == "" {
			continue
		}

		_, exists := preamble.Get(p)
		if !exists {
			preamble.Set(p, true)
		}
	}

	result := ""
	for _, k := range preamble.Keys() {
		result += k + "\n"
	}

	return self.indent(result, "    ")
}

func (self *Compiler) indent(in string, indent string) string {
	lines := strings.Split(in, "\n")
	result := make([]string, 0, len(lines))
	for _, l := range lines {
		result = append(result, indent+l)
	}

	return strings.Join(result, "\n")
}

func (self *Compiler) saveFile(filename string, item interface{}) error {
	out_fd, err := os.OpenFile(filename,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out_fd.Close()

	serialized, err := yaml.Marshal(item)
	if err != nil {
		return err
	}

	_, err = out_fd.Write(serialized)
	return err
}

func (self *Compiler) buildCategories() (result []string) {
	for k := range self.categories {
		result = append(result, k)
	}

	sort.Strings(result)
	return result
}

func (self *Compiler) GetRules() []byte {
	serialized, _ := yaml.Marshal(self.rules)
	return serialized
}

func (self *Compiler) Compile() (string, error) {
	tmpl, err := template.New("").Parse(artifact_template)
	if err != nil {
		return "", err
	}

	categories := self.buildCategories()
	parameters := &templateParameters{
		Name:           "Windows.Registry.Hunter",
		Metadata:       self.buildMetadata(),
		Rules:          self.rules,
		Preamble:       self.buildPreamble(),
		Categories:     categories,
		CategoriesJSON: self.serialize(categories),
		QueriesJSON:    self.compress(self.serialize(self.queries)),
		Time:           time.Now().UTC().Format(time.RFC3339),
	}

	var b bytes.Buffer
	err = tmpl.Execute(&b, parameters)
	return string(b.Bytes()), err
}
