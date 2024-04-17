all: build recmd artifact artifact_zip

build:
	go build -o reghunter ./bin/

# Convert the RECMD batch files to Registry Hunter yaml files.
recmd:
	./reghunter convert --output Rules/RECmdBatch.yaml RECmd_Batch/*.reb

# Build the YAML artifact
artifact:
	./reghunter compile --output output/Windows.Registry.Hunter.yaml Rules/*.yaml

# Build the ZIP file for importing
artifact_zip:
	./reghunter compile --make_zip --output output/Windows.Registry.Hunter.zip Rules/*.yaml

test:
	cd tests && make test


test_update:
	cd tests && make test_update
