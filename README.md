# Registry Hunter

This repository aims to simplify the process of inspecting the
Registry for forensically relevant details.

This project is inspired by the RECmd Batch files project
(https://github.com/EricZimmerman/RECmd/tree/master/BatchExamples)

## How does it work?

This project maintains a set of `Rules` which are YAML files following
a simple format. This project implements a compiler which compiles
these rules into a VQL artifact that may be consumed by Velociraptor.

The Rule file starts with the attibute Rules and contains a list of
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
  https://docs.velociraptor.app/vql_reference/plugin/glob/ ) the will
  search the registry under the Root key.
* Root: The is a root registry path. This can only be one of the
  following values as described below
