# Command line

Building a command line application in `GOLANG` using the [`COBRA` library](https://github.com/spf13/cobra).

> Cobra [user guide](https://github.com/spf13/cobra/blob/main/user_guide.md)

## Install 

> Cobra is built on a structure of commands, arguments & flags.


### Step 1. Download and install

```bash
go get -u github.com/spf13/cobra
```

```go
import "github.com/spf13/cobra"
```

## Adding functionality

### Milestone - 1
Let's add a small command to invoke from the main function as follows.

```go
var (
	rootCmd = &cobra.Command{
		Use:   "hello",
		Short: "A simple echo",
		Long:  "Allows you to validate the command output via a message returned.",
		Run: func(cmd *cobra.Command, args []string) {
			log.Println(" Run Hello!")
			if len(args) < 1 {
				log.Println("Invalid usage: ")
				cmd.Help()
				os.Exit(1)
			}
		},
	}
)
```

In the code above we define the command and no flags for the command, yet we check for the length of arguments and print the help in case the command is invoked.

The rest of tha `main.go` looks like

```go
func init() {
	log.Println(" Initalise called!")
}

func main() {
	fmt.Println(" Hello World!")
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```

```bash
> go run src/main.go

2022/09/07 16:35:28  Initalise called!
 Hello World!
2022/09/07 16:35:28  Run Hello!
2022/09/07 16:35:28 Invalid usage: 
Allows you to validate the command output via a message returned.

Usage:
  hello [flags]

Flags:
  -h, --help   help for hello
exit status 1
```

### Milestone - 2

Let's add some flags and process appropriately. We will define the flag `MessageFlag` that we will use as a constant and use it subsequently.

```bash
const (
	// MessageFlag defines the Message to display. Default vault is Hello World!
	MessageFlag = "message"
)
```

Modifying the `function init` to add the [parameter](https://pkg.go.dev/github.com/spf13/pflag#StringVarP). This function takes an argument as pointer to the variable that will store the variable value as passed on the command line.


```bash
func init() {
	log.Println(" Initalise called!")
	rootCmd.Flags().StringVarP(&message, MessageFlag, "m", "Hello World!", "Message that will be displayed")
}
```

Defining the variable `message` in the var section & modify the `Run` section as under to process the flag.

```bash
var (
	message string
	rootCmd = &cobra.Command{
		Use:        "hello",
		Short:      "A simple echo",
		Long:       "Allows you to validate the command output via a message returned.",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				log.Println("Invalid usage: ")
				cmd.Help()
				os.Exit(1)
			}
			log.Printf(" Flags: %v", message)
			fmt.Printf(">> %s<<\n", message)
		},
	}
)
```

#### Test output

##### No Flag Check

```bash
cmd-line % go run src/main.go helo
2022/09/08 09:48:42  Initalise called!
 Hello World!
2022/09/08 09:48:42  Flags:  Hello World!
>> Hello World!<<
```

##### With flag `-m`

```bash
cmd-line % go run src/main.go helo -m Wow!
2022/09/08 09:49:26  Initalise called!
 Hello World!
2022/09/08 09:49:26  Flags: Wow!
>> Wow!<<
```

##### With long flag `--message`

```bash
cmd-line % go run src/main.go helo --message Wow!
2022/09/08 09:57:21  Initalise called!
2022/09/08 09:57:21  Flags: Wow!
>> Wow!<<
```

## Building the binary

```bash
env GOOS=linux GOARCH=arm64 go build  -o ../target/vault-agent main.go
```