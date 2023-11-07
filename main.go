package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/caarlos0/env"
	"os"
	"os/exec"
	"strings"
)

type RegistryCredential struct {
	RegistryType       string `json:"registryType"`
	RegistryURL        string `json:"registryURL"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	AWSAccessKeyId     string `json:"awsAccessKeyId,omitempty"`
	AWSSecretAccessKey string `json:"awsSecretAccessKey,omitempty"`
	AWSRegion          string `json:"awsRegion,omitempty"`
}

const (
	REGISTRY_TYPE_ECR                     = "ecr"
	REGISTRYTYPE_GCR                      = "gcr"
	REGISTRYTYPE_ARTIFACT_REGISTRY        = "artifact-registry"
	JSON_KEY_USERNAME              string = "_json_key"
)

const (
	SOURCE_REGISTRY_CREDENTIAL_KEY = "SOURCE_REGISTRY_CREDENTIAL"
)

type SkopeoPluginInputVariables struct {
	DestinationInfo             string `env:"DESTINATION_INFO"`
	SourceImage                 string `env:"DOCKER_IMAGE"`
	RegistryDestinationImageMap string `env:"REGISTRY_DESTINATION_IMAGE_MAP"`
	RegistryCredentials         string `env:"REGISTRY_CREDENTIALS"`
}

func main() {

	CopyImagesRequest := &SkopeoPluginInputVariables{}
	err := env.Parse(CopyImagesRequest)
	if err != nil {
		fmt.Println("Error in parsing input variables", "err", err)
		return
	}

	var registryCredentials map[string]RegistryCredential
	fmt.Println(CopyImagesRequest.RegistryCredentials)
	err = json.Unmarshal([]byte(CopyImagesRequest.RegistryCredentials), &registryCredentials)
	if err != nil {
		fmt.Printf("Error in parsin registry credentials")
		fmt.Println(err.Error())
		os.Exit(1)
	}

	var registryDestinationImageMap map[string][]string
	fmt.Println(CopyImagesRequest.RegistryDestinationImageMap)
	err = json.Unmarshal([]byte(CopyImagesRequest.RegistryDestinationImageMap), &registryDestinationImageMap)
	if err != nil {
		fmt.Printf("error in parsing registryDestinationImageMap")
		fmt.Println(err.Error())
		os.Exit(1)
	}

	err = copyImages(CopyImagesRequest.SourceImage, registryDestinationImageMap, registryCredentials)
	if err != nil {
		os.Exit(1)
	}
	fmt.Println("Copy operation successfully completed")

}

func copyImages(sourceImage string, destinationRegistryImageMap map[string][]string, registryCredentials map[string]RegistryCredential) error {
	sourceRegistryCredential := registryCredentials[SOURCE_REGISTRY_CREDENTIAL_KEY]
	for destinationRegistry, destinationImages := range destinationRegistryImageMap {
		destinationRegistryCredential, ok := registryCredentials[destinationRegistry]
		if ok {
			username, password, err := ExtractCredentialsForRegistry(destinationRegistryCredential)
			if err != nil {
				fmt.Printf(err.Error())
				os.Exit(1)
			}
			destinationRegistryCredential.Username = username
			destinationRegistryCredential.Password = password
			for _, destinationImage := range destinationImages {
				err := execSkopeoCommand(sourceImage, destinationImage, sourceRegistryCredential, destinationRegistryCredential)
				if err != nil {
					fmt.Printf("error in copying image; sourceImage: %s destinationImage: %s ; ERROR:(%s)", sourceImage, destinationImage, err.Error())
					os.Exit(1)
				}
			}
		} else {
			fmt.Printf("Registry credentials not provided for registry - %s", destinationRegistry)
			os.Exit(1)
		}
	}
	return nil
}

func ExtractCredentialsForRegistry(registryCredential RegistryCredential) (string, string, error) {
	username := registryCredential.Username
	pwd := registryCredential.Password
	if (registryCredential.RegistryType == REGISTRYTYPE_GCR || registryCredential.RegistryType == REGISTRYTYPE_ARTIFACT_REGISTRY) && username == JSON_KEY_USERNAME {
		if strings.HasPrefix(pwd, "'") {
			pwd = pwd[1:]
		}
		if strings.HasSuffix(pwd, "'") {
			pwd = pwd[:len(pwd)-1]
		}
	}
	if registryCredential.RegistryType == REGISTRY_TYPE_ECR {
		accessKey, secretKey := registryCredential.AWSAccessKeyId, registryCredential.AWSSecretAccessKey
		var creds *credentials.Credentials

		if len(registryCredential.AWSAccessKeyId) == 0 || len(registryCredential.AWSSecretAccessKey) == 0 {
			sess, err := session.NewSession(&aws.Config{
				Region: &registryCredential.AWSRegion,
			})
			if err != nil {
				fmt.Printf("Error in creating AWS client", "err", err)
				return "", "", err
			}
			creds = ec2rolecreds.NewCredentials(sess)
		} else {
			creds = credentials.NewStaticCredentials(accessKey, secretKey, "")
		}
		sess, err := session.NewSession(&aws.Config{
			Region:      &registryCredential.AWSRegion,
			Credentials: creds,
		})
		if err != nil {
			fmt.Println("Error in creating AWS client session", "err", err)
			return "", "", err
		}
		svc := ecr.New(sess)
		input := &ecr.GetAuthorizationTokenInput{}
		authData, err := svc.GetAuthorizationToken(input)
		if err != nil {
			fmt.Println("Error fetching authData", "err", err)
			return "", "", err
		}
		// decode token
		token := authData.AuthorizationData[0].AuthorizationToken
		decodedToken, err := base64.StdEncoding.DecodeString(*token)
		if err != nil {
			fmt.Println("Error in decoding auth token", "err", err)
			return "", "", err
		}
		credsSlice := strings.Split(string(decodedToken), ":")
		username = credsSlice[0]
		pwd = credsSlice[1]
	}
	return username, pwd, nil
}

func execSkopeoCommand(sourceImage, destinationImage string, sourceRegistryCredential, destinationRegistryCredential RegistryCredential) error {
	skopeoCommand := "skopeo"
	skopeoArgs := []string{
		"copy",
		"--src-creds=" + sourceRegistryCredential.Username + ":" + sourceRegistryCredential.Password,
		"docker://" + sourceImage,
		"--dest-creds=" + destinationRegistryCredential.Username + ":" + destinationRegistryCredential.Password,
		"docker://" + destinationImage,
	}
	cmd := exec.Command(skopeoCommand, skopeoArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error running Skopeo: %v\n", err)
		return err
	}
	return nil
}
