package io

import (
	"io/ioutil"
	"os"
)

// ReadJSONFiles reads the json files of a given folder
func ReadJSONFiles(folder string) (map[string][]byte, error) {
	var fileInfo, err = ioutil.ReadDir(folder)
	if err != nil {
		return nil, err
	}

	var files = make(map[string][]byte)
	for _, file := range fileInfo {
		if !file.IsDir() && len(file.Name()) > 5 && file.Name()[len(file.Name())-5:] == ".json" {
			var fileContent []byte
			fileContent, err = ReadFileBytes(folder + "/" + file.Name())
			if err != nil {
				return nil, err
			}
			files[file.Name()[0:len(file.Name())-5]] = fileContent
		}
	}
	return files, nil
}

// ReadFileBytes returns file content as a slice of bytes
func ReadFileBytes(filename string) ([]byte, error) {
	var osfile, err = os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer osfile.Close()

	var bytes []byte
	bytes, err = ioutil.ReadAll(osfile)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}
