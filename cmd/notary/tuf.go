package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	"github.com/endophage/gotuf"
	"github.com/endophage/gotuf/client"
	"github.com/endophage/gotuf/data"
	"github.com/endophage/gotuf/keys"
	"github.com/endophage/gotuf/signed"
	"github.com/endophage/gotuf/store"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cmdTuf = &cobra.Command{
	Use:   "tuf [ GUN ]",
	Short: "Manages trust of data for notary. Lists targets for GUN when no other command given",
	Long:  "Segments all commands related to managing TUF metadata. In the absence of another command, it lists all targets found under the Globally Unique Name.",
	Run:   tufList,
}

var remoteTrustServer string

func init() {
	cmdTuf.AddCommand(cmdTufInit)
	cmdTuf.AddCommand(cmdTufAdd)
	cmdTuf.AddCommand(cmdTufRemove)
	cmdTuf.AddCommand(cmdTufPush)
	cmdTufPush.Flags().StringVarP(&remoteTrustServer, "remote", "r", "", "Remote trust server location")
	cmdTuf.AddCommand(cmdTufLookup)
	cmdTufLookup.Flags().StringVarP(&remoteTrustServer, "remote", "r", "", "Remote trust server location")
}

var cmdTufAdd = &cobra.Command{
	Use:   "add [ GUN ] <target> <file path>",
	Short: "pushes local updates.",
	Long:  "pushes all local updates within a specific TUF repo to remote trust server.",
	Run:   tufAdd,
}

var cmdTufRemove = &cobra.Command{
	Use:   "remove [ GUN ] <target>",
	Short: "Removes a target from the TUF repo.",
	Long:  "removes a target from the local TUF repo identified by a Globally Unique Name.",
	Run:   tufRemove,
}

var cmdTufInit = &cobra.Command{
	Use:   "init [ GUN ]",
	Short: "initializes the local TUF repository.",
	Long:  "creates locally the initial set of TUF metadata for the Globally Unique Name.",
	Run:   tufInit,
}

var cmdTufLookup = &cobra.Command{
	Use:   "lookup [ GUN ] <target name>",
	Short: "Looks up a specific TUF target in a repository.",
	Long:  "looks up a TUF target in a repository given a Globally Unique Name.",
	Run:   tufLookup,
}

var cmdTufPush = &cobra.Command{
	Use:   "push [ GUN ]",
	Short: "initializes the local TUF repository.",
	Long:  "creates locally the initial set of TUF metadata for the Globally Unique Name.",
	Run:   tufPush,
}

func tufAdd(cmd *cobra.Command, args []string) {
	if len(args) < 3 {
		cmd.Usage()
		fatalf("must specify a GUN, target name, and local path to target data")
	}

	gun := args[0]
	targetName := args[1]
	targetPath := args[2]
	kdb := keys.NewDB()
	signer := signed.NewSigner(NewCryptoService(gun))
	repo := tuf.NewTufRepo(kdb, signer)

	filestore, err := store.NewFilesystemStore(
		path.Join(viper.GetString("tufDir"), gun),
		"metadata",
		"json",
		"targets",
	)

	b, err := ioutil.ReadFile(targetPath)
	if err != nil {
		fatalf(err.Error())
	}

	rootJSON, err := filestore.GetMeta("root", 0)
	if err != nil {
		fatalf(err.Error())
	}
	root := &data.Signed{}
	err = json.Unmarshal(rootJSON, root)
	if err != nil {
		fatalf(err.Error())
	}
	repo.SetRoot(root)
	targetsJSON, err := filestore.GetMeta("targets", 0)
	if err != nil {
		fatalf(err.Error())
	}
	targets := &data.Signed{}
	err = json.Unmarshal(targetsJSON, targets)
	if err != nil {
		fatalf(err.Error())
	}
	repo.SetTargets("targets", targets)
	snapshotJSON, err := filestore.GetMeta("snapshot", 0)
	if err != nil {
		fatalf(err.Error())
	}
	snapshot := &data.Signed{}
	err = json.Unmarshal(snapshotJSON, snapshot)
	if err != nil {
		fatalf(err.Error())
	}
	repo.SetSnapshot(snapshot)
	timestampJSON, err := filestore.GetMeta("timestamp", 0)
	if err != nil {
		fatalf(err.Error())
	}
	timestamp := &data.Signed{}
	err = json.Unmarshal(timestampJSON, timestamp)
	if err != nil {
		fatalf(err.Error())
	}
	repo.SetTimestamp(timestamp)

	meta, err := data.NewFileMeta(bytes.NewBuffer(b))
	if err != nil {
		fatalf(err.Error())
	}

	_, err = repo.AddTargets("targets", data.Files{targetName: meta})
	if err != nil {
		fatalf(err.Error())
	}

	saveRepo(repo, filestore)
}

func tufInit(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		fatalf("Must specify a GUN")
	}

	gun := args[0]
	kdb := keys.NewDB()
	signer := signed.NewSigner(NewCryptoService(gun))

	rootKey, err := signer.Create()
	targetsKey, err := signer.Create()
	snapshotKey, err := signer.Create()
	timestampKey, err := signer.Create()

	kdb.AddKey(rootKey)
	kdb.AddKey(targetsKey)
	kdb.AddKey(snapshotKey)
	kdb.AddKey(timestampKey)

	rootRole, err := data.NewRole("root", 1, []string{rootKey.ID()}, nil, nil)
	targetsRole, err := data.NewRole("targets", 1, []string{targetsKey.ID()}, nil, nil)
	snapshotRole, err := data.NewRole("snapshot", 1, []string{snapshotKey.ID()}, nil, nil)
	timestampRole, err := data.NewRole("timestamp", 1, []string{timestampKey.ID()}, nil, nil)

	kdb.AddRole(rootRole)
	kdb.AddRole(targetsRole)
	kdb.AddRole(snapshotRole)
	kdb.AddRole(timestampRole)

	repo := tuf.NewTufRepo(kdb, signer)

	filestore, err := store.NewFilesystemStore(
		path.Join(viper.GetString("tufDir"), gun), // TODO: base trust dir from config
		"metadata",
		"json",
		"targets",
	)
	if err != nil {
		fatalf(err.Error())
	}

	err = repo.InitRepo(false)
	if err != nil {
		fatalf(err.Error())
	}
	saveRepo(repo, filestore)
}

func tufList(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		fatalf("must specify a GUN")
	}
	gun := args[0]
	kdb := keys.NewDB()
	repo := tuf.NewTufRepo(kdb, nil)

	remote, err := store.NewHTTPStore(
		"https://vetinari:4443/v2/"+gun+"/_trust/tuf/",
		"",
		"json",
		"",
	)
	rootJSON, err := remote.GetMeta("root", 5<<20)
	if err != nil {
		fmt.Println("Couldn't get initial root")
		fatalf(err.Error())
	}
	root := &data.Signed{}
	err = json.Unmarshal(rootJSON, root)
	if err != nil {
		fmt.Println("Couldn't parse initial root")
		fatalf(err.Error())
	}
	// TODO: Validate the root file against the key store
	err = repo.SetRoot(root)
	if err != nil {
		fmt.Println("Error setting root")
		fatalf(err.Error())
	}

	c := client.NewClient(
		repo,
		remote,
		kdb,
	)

	err = c.Update()
	if err != nil {
		fmt.Println("Update failed")
		fatalf(err.Error())
	}
	for name, meta := range repo.Targets["targets"].Signed.Targets {
		fmt.Println(name, " ", meta.Hashes["sha256"], " ", meta.Length)
	}
}

func tufLookup(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		cmd.Usage()
		fatalf("must specify a GUN and target path to look up.")
	}

	gun := args[0]
	targetName := args[1]
	kdb := keys.NewDB()
	repo := tuf.NewTufRepo(kdb, nil)

	remote, err := store.NewHTTPStore(
		"https://localhost:4443/v2"+gun+"/_trust/tuf/",
		"",
		"json",
		"",
	)

	rootJSON, err := remote.GetMeta("root", 0)
	root := &data.Signed{}
	err = json.Unmarshal(rootJSON, root)
	if err != nil {
		fatalf(err.Error())
	}
	// TODO: Validate the root file against the key store
	repo.SetRoot(root)

	c := client.NewClient(
		repo,
		remote,
		kdb,
	)

	err = c.Update()
	if err != nil {
		fatalf(err.Error())
	}
	m := c.TargetMeta(targetName)
	// TODO: how to we want to output hash and size
	fmt.Println(m.Hashes["sha256"], " ", m.Length)
}

func tufPush(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		fatalf("must specify a GUN")
	}

	gun := args[0]

	remote, err := store.NewHTTPStore(
		"https://vetinari:4443/v2/"+gun+"/_trust/tuf/",
		"",
		"json",
		"",
	)
	filestore, err := store.NewFilesystemStore(
		path.Join(viper.GetString("tufDir"), gun),
		"metadata",
		"json",
		"targets",
	)

	root, err := filestore.GetMeta("root", 0)
	if err != nil {
		fatalf(err.Error())
	}
	targets, err := filestore.GetMeta("targets", 0)
	if err != nil {
		fatalf(err.Error())
	}
	snapshot, err := filestore.GetMeta("snapshot", 0)
	if err != nil {
		fatalf(err.Error())
	}
	timestamp, err := filestore.GetMeta("timestamp", 0)
	if err != nil {
		fatalf(err.Error())
	}

	err = remote.SetMeta("root", root)
	if err != nil {
		fatalf(err.Error())
	}
	err = remote.SetMeta("targets", targets)
	if err != nil {
		fatalf(err.Error())
	}
	err = remote.SetMeta("snapshot", snapshot)
	if err != nil {
		fatalf(err.Error())
	}
	err = remote.SetMeta("timestamp", timestamp)
	if err != nil {
		fatalf(err.Error())
	}
}

func tufRemove(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		fatalf("must specify a GUN")
	}
}

func saveRepo(repo *tuf.TufRepo, filestore store.MetadataStore) error {
	signedRoot, err := repo.SignRoot(data.DefaultExpires("root"))
	if err != nil {
		return err
	}
	fmt.Println("Marshalling root")
	rootJSON, _ := json.Marshal(signedRoot)
	filestore.SetMeta("root", rootJSON)

	for r, _ := range repo.Targets {
		fmt.Println("Marshalling ", r)
		signedTargets, err := repo.SignTargets(r, data.DefaultExpires("targets"))
		if err != nil {
			return err
		}
		targetsJSON, _ := json.Marshal(signedTargets)
		parentDir := filepath.Dir(r)
		os.MkdirAll(parentDir, 0755)
		filestore.SetMeta(r, targetsJSON)
	}

	signedSnapshot, err := repo.SignSnapshot(data.DefaultExpires("snapshot"))
	if err != nil {
		return err
	}
	fmt.Println("Marshalling snapshot")
	snapshotJSON, _ := json.Marshal(signedSnapshot)
	filestore.SetMeta("snapshot", snapshotJSON)

	signedTimestamp, err := repo.SignTimestamp(data.DefaultExpires("timestamp"))
	if err != nil {
		return err
	}
	fmt.Println("Marshalling timestamp")
	timestampJSON, _ := json.Marshal(signedTimestamp)
	filestore.SetMeta("timestamp", timestampJSON)
	return nil
}