all: build artifact artifact_zip

build:
	go build -o reghunter ./bin/

# Convert the RECMD batch files to Registry Hunter yaml files. Note
# really used any more as we do not directly use RECmd batch files any
# more.
recmd_convert: build
	./reghunter convert --output Rules/RECmdBatch.yaml RECmd_Batch/*.reb

verify_recmd: build
	./reghunter verify recmd --recmddir RECmd_Batch/ --mapping RECmd_Batch/Mapping.yaml Rules/*.yaml

# Build the YAML artifact
artifact: build
	./reghunter compile --output output/Windows.Registry.Hunter.yaml --meta output/Windows.Registry.Hunter.Meta.yaml Rules/*.yaml

# Build the ZIP file for importing
artifact_zip:
	./reghunter compile --make_zip --output output/Windows.Registry.Hunter.zip --index docs/content/docs/rules/index.json Rules/*.yaml

test:
	cd tests && make test

verify: build verify_recmd artifact
	./tests/velociraptor artifacts verify -v ./output/*.yaml

test_update:
	cd tests && make test_update
