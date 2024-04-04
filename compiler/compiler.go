package compiler

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"text/template"

	"github.com/Velocidex/ordereddict"
	"github.com/Velocidex/registry_hunter/config"
	"github.com/Velocidex/yaml/v2"
)

const (
	artifact_template = `
name: {{.Name}}
description: |
   This artifact parses and categorizes information for the registry.

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

export: |
    LET _info <= SELECT * FROM info()

    -- On Non Windows systems we need to use case insensitive accessor or we might not find the right hives.
    LET DefaultAccessor <= if(condition=_info[0].OS =~ "windows", then="raw_ntfs", else="file_nocase")
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
      RegistryPath="HKEY_USERS\\" + OSPath[-2] + "\\NTUser.dat") AS Mapping
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

    LET _MD <= parse_json_array(data=gunzip(string=base64decode(string="{{.Metadata }}")))
    LET MD(DescriptionFilter, RootFilter, CategoryFilter, CategoryExcludedFilter) = SELECT * FROM _MD
     WHERE Description =~ DescriptionFilter
       AND Root =~ RootFilter
       AND Category =~ CategoryFilter
       AND NOT Category =~ CategoryExcludedFilter

sources:
- name: Remapping
  query: |
    SELECT * FROM RemapRules

- name: Rules
  query: |
    LET AllRules <=
      SELECT * FROM MD(DescriptionFilter=DescriptionFilter, RootFilter=RootFilter,
        CategoryFilter=CategoryFilter, CategoryExcludedFilter=CategoryExcludedFilter)
    SELECT * FROM AllRules

- name: Globs
  query: |
    LET AllGlobs <=
      SELECT Root, enumerate(items=Glob) AS Globs
      FROM AllRules
      GROUP BY Root

    SELECT * FROM AllGlobs

- query: |
    LET GlobsMD <= to_dict(item={
      SELECT Root AS _key, Globs AS _value FROM AllGlobs
    })

    LET s = scope()

    LET Cache <= memoize(query={
       SELECT Glob, Category, Description, s.Details AS Details, s.Comment AS Comment, s.Filter AS Filter
       FROM AllRules
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
    }, workers=20)

    SELECT Metadata.Description AS Description,
           Metadata.Category AS Category,
           OSPath, Mtime, Data AS _RawData,
           eval(func=Metadata.Details || "x=>x.Data") || Data AS Details,
           Metadata AS _Metadata
    FROM Result
    WHERE eval(func=Metadata.Filter || "x=>NOT IsDir")
      AND Category =~ CategoryFilter
      AND Metadata.Description =~ DescriptionFilter
`
)

type templateParameters struct {
	Name     string
	Metadata string
	Rules    []config.RegistryRule
	Preamble string

	Categories     []string
	CategoriesJSON string
}

type Compiler struct {
	rules []config.RegistryRule
	md    map[string]config.RegistryRule

	// Groups the globs by root and globs
	globs map[string][]string

	PreambleVerses []string

	categories map[string]bool
}

func NewCompiler() *Compiler {
	return &Compiler{
		md:         make(map[string]config.RegistryRule),
		globs:      make(map[string][]string),
		categories: make(map[string]bool),
	}
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

	// Add preables from rules
	for _, r := range rules.Rules {
		if len(r.Preamble) > 0 {
			self.PreambleVerses = append(self.PreambleVerses, r.Preamble...)
		}
		self.categories[r.Category] = true
		self.rules = append(self.rules, r)
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
	serialized, err := json.Marshal(categories)
	if err != nil {
		return "", err
	}

	parameters := &templateParameters{
		Name:           "Windows.Registry.Hunter",
		Metadata:       self.buildMetadata(),
		Rules:          self.rules,
		Preamble:       self.buildPreamble(),
		Categories:     categories,
		CategoriesJSON: string(serialized),
	}

	var b bytes.Buffer
	err = tmpl.Execute(&b, parameters)
	return string(b.Bytes()), err
}
