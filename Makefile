all:
	go build -o reghunter ./bin/

# Convert the RECMD batch files to Registry Hunter yaml files.
recmd:
	./reghunter convert --output Rules/RECmdBatch.yaml RECmd_Batch/*.reb

artifact:
	./reghunter compile --output output/Windows.Registry.Hunter.yaml Rules/*.yaml
	./reghunter compile --make_zip --output output/Windows.Registry.Hunter.zip Rules/*.yaml

test:
	cd tests && make test
