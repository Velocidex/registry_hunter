# Registry Hunter

This repository aims to simplify the process of inspecting the
Registry for forensically relevant details.

This project is inspired by the following projects:

1. [The RECmd Batch files project](https://github.com/EricZimmerman/RECmd/tree/master/BatchExamples)
2. [RegRipper](https://github.com/keydet89/RegRipper4.0)

The intention of this project is to produce a single artifact
incorporating many analysis modules (called Rules). The user would
simply need to collect a single artifact from the endpoint and receive
a wide number of analysis output in machine readable format in
minutes.

This simplifies the process of collection and analysis as the user
does not need to remember the hundreds of separate Velociraptor
artifacts and collect many different artifacts.

The artifact is also designed to simplify running in various
situations:

1. Live analysis: Running on a live endpoint
2. Analysis of separate collected hive files (e.g. post processing a
   Triage).
3. Running over a dead disk image.

## How does it work?

This project maintains a set of `Rules` which are YAML files following
a simple format. This project implements a compiler which compiles
these rules into a VQL artifact that may be consumed by Velociraptor.

The Rule file starts with the attribute `Rules` and contains a list of
rules:

```
Rules:
- Author: Andrew Rathbun
  Description: Prefetch Status
  Category: System Info
  Comment: 0 = Disabled, 1 = Application Prefetching Enabled, 2 = Boot Prefetching
    Enabled, 3 = Application and Boot Prefetching Enabled
  Glob: ControlSet00*\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher
  Root: HKEY_LOCAL_MACHINE\System
```

* Author: This is the name of the author or the rule (optional)
* Description: The description will be shown in the generated artifact
  output
* Category: The category will be shown in the generated artifact
  output
* Comment: The comment will be shown in the generated artifact output
* Glob: The glob represents a search expression (See
  https://docs.velociraptor.app/vql_reference/plugin/glob/ ) this will
  search the registry under the Root key.
* Root: The is a root registry path. This can only be one of the
  following values as described below

## What is a `Remapping Strategy`?

The Windows registry consists of a number of hives "mounted" onto a
single logical hierarchy. For example, the `HKEY_USERS` hive consists
each currently logged in user's `NTUser.DAT` hive file mounted within
it.

If we just relied on the API to fetch keys from the `HKEY_USERS` hive,
we would only be able to see currently logged in users. Users that are
not currently logged in will not have their `NTUSER.DAT` file
analysed.

Similarly other parts of the registry are not accessible via the API -
for example the `SAM` or `Amcache`.

Therefore the registry hunter artifact constructs a virtual hierarchy
and automatically mounts various hives on these mount points. This is
necesary even when using the API.

The different remapping strategies describe how the virtual hierarchy
is constructed (Note that the system itself does not mount the
registry hives! the hives are logically remapped for the purpose of
Velociraptor's VQL engine):

* The `API And NTUser.dat` strategy mounts all user's `NTUSER.DAT`
  over the `HKEY_USERS` key. This allows the rule to address all user
  hives without needing to worry about raw registry parsing of
  non-logged in users.
* The `SAM` is mounted under `/SAM`

### How to use on a dead disk image?

The Registry Hunter can be used on a dead disk image by first creating
a remapping file for the image. This is described in details in [Remapping Accessors](https://docs.velociraptor.app/docs/forensic/filesystem/remapping/) and [Dead Disk Analysis](https://docs.velociraptor.app/blog/2022/2022-03-22-deaddisk/).

Briefly use the following procedure:

1. Generate a remapping file for the disk image:

```
$velociraptor-linux-amd64 -v deaddisk --add_windows_disk /path/to/image.vmdk /tmp/remapping.yaml
```

After checking the remapping file, you can start a Velociraptor client
with it - this creates a "Virtual Client" which can collect artifacts
directly from the image.

To start a client/server "instant Velociraptor":

```
velociraptor-linux-amd64 --remap /tmp/remapping.yaml gui -v
```

Alternatively to start a remapped client that connects to a remote server:

```
velociraptor-linux-amd64 --remap /tmp/remapping.yaml client -v
```

You can now collect the Registry Hunter artifact with the "None"
Remapping Strategy.


## How to easily develop new rules?

The artifact generated contains a large number of rules and it is
designed to collect them all at once. This makes it hard to develop as
we need a quick development cycle (build -> test -> inspect cycle).

I usually use a Windows test VM with a shared drive that I can used to
exchange data with the development system.

I run `velociraptor.exe gui` on the development VM to create an
instant Velociraptor server and client. This way I can use the
notebook directly on Windows and develop/test my artifacts.

On the development system:

```
$ make && cp output/Windows.Registry.Hunter.yaml  /shared/reghunter/
```

This builds the artifacts and copies onto a shared directory which I
can exchange with the Windows test VM.

On the test VM I create a notebook and enter the following query. Here
`F:` is the shared drive mount letter on the Windows system.

```sql
LET RuleName = "Active Setup Installed Components"

LET _ <= SELECT artifact_set(definition=read_file(filename=OSPath)).name AS Name
FROM glob(globs="F:/reghunter/*")

SELECT * FROM Artifact.Windows.Registry.Hunter(
   CollectionPolicy="HashOnly",
   RuleFilter=RuleName)
WHERE _Source =~ "Results"

```

In the above example, I am working on a rule called `Active Setup
Installed Components`. The above query:

1. Imports the new artifact that was just built from the shared folder.
2. Runs the artifact with the HashOnly collection policy (This is a
   bit faster than uploading all the targets).
3. The results are shown from the Results source.

Iterating is now very quick - I just rebuild the artifact in my dev
system, and refresh the cell in the test system.
