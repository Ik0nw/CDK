/*
Copyright 2022 The Authors of https://github.com/CDK-TEAM/CDK .

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/cdk-team/CDK/pkg/errors"
)

func IsDirectory(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fileInfo.IsDir()
}

// ReadLines reads a whole file into memory
// and returns a slice of its lines.
// Uses StealthReadFile to avoid libc open/read hooks.
func ReadLines(path string) ([]string, error) {
	data, err := StealthReadFile(path)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

func FileExist(path string) bool {
	fileInfo, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !fileInfo.IsDir()
}

func IsSoftLink(FilePath string) bool {
	fileInfo, err := os.Lstat(FilePath)
	if err != nil {
		return false
	}
	return fileInfo.Mode()&os.ModeSymlink != 0
}

func IsDir(FilePath string) bool {
	fileInfo, err := os.Stat(FilePath)
	if err != nil {
		return false
	}
	return fileInfo.IsDir()
}

func RewriteFile(path string, content string, perm os.FileMode) {
	cmdFile, err := os.OpenFile(path, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, perm)
	if err != nil {
		log.Fatal("overwrite file:", path, "err: "+err.Error())
	} else {
		n, _ := cmdFile.Seek(0, io.SeekEnd)
		_, err = cmdFile.WriteAt([]byte(content), n)
		log.Println("overwrite file:", path, "success.")
		defer cmdFile.Close()
	}
}

func WriteFile(path string, content string) error {
	return os.WriteFile(path, []byte(content), 0666)
}

func WriteFileAdd(path string, content string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	_, err = file.Write([]byte(content))
	if err != nil {
		return err
	}
	file.Close()
	return nil
}

func WriteShellcodeToCrontab(header string, filePath string, shellcode string) error {
	shellcode = fmt.Sprintf("\n%s\n* * * * * root %s", header, shellcode)
	err := WriteFileAdd(filePath, shellcode)
	if err != nil {
		return &errors.CDKRuntimeError{Err: err, CustomMsg: "err found while writing shellcode to host crontab from container."}
	}
	return nil
}
