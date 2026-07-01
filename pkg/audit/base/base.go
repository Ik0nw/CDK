package base

type BaseExploit struct {
	ExploitType   string
	ActivePrereqs []string
	ArgPrereqs    func(args []string) []string
}

func (b BaseExploit) GetExploitType() string {
	return b.ExploitType
}

func (b BaseExploit) PreflightPrereqs(args []string) []string {
	if b.ArgPrereqs != nil {
		return b.ArgPrereqs(args)
	}
	return b.ActivePrereqs
}
