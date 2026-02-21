import { Command } from "commander";

const BASH_COMPLETION = `
# rafter bash completion
# Add to ~/.bashrc: eval "$(rafter completion bash)"
_rafter_completion() {
  local cur prev words
  COMPREPLY=()
  cur="\${COMP_WORDS[COMP_CWORD]}"
  prev="\${COMP_WORDS[COMP_CWORD-1]}"
  words="\${COMP_WORDS[*]}"

  local top_cmds="run scan get usage agent ci hook mcp policy completion --help --version"
  local agent_cmds="init scan exec config audit audit-skill install-hook verify status"
  local ci_cmds="init"
  local hook_cmds="pretool posttool"
  local policy_cmds="export"

  if [[ \${COMP_CWORD} -eq 1 ]]; then
    COMPREPLY=( \$(compgen -W "\${top_cmds}" -- "\${cur}") )
    return 0
  fi

  case "\${COMP_WORDS[1]}" in
    agent)
      if [[ \${COMP_CWORD} -eq 2 ]]; then
        COMPREPLY=( \$(compgen -W "\${agent_cmds}" -- "\${cur}") )
      fi
      case "\${COMP_WORDS[2]}" in
        scan)  COMPREPLY=( \$(compgen -W "--quiet --json --format --staged --diff --engine" -- "\${cur}") ) ;;
        init)  COMPREPLY=( \$(compgen -W "--risk-level --skip-gitleaks --skip-openclaw --skip-claude-code --force" -- "\${cur}") ) ;;
        verify) COMPREPLY=() ;;
        status) COMPREPLY=() ;;
        audit-skill) COMPREPLY=( \$(compgen -W "--skip-openclaw --json" -- "\${cur}") ) ;;
        install-hook) COMPREPLY=( \$(compgen -W "--global" -- "\${cur}") ) ;;
        config) COMPREPLY=( \$(compgen -W "show get set" -- "\${cur}") ) ;;
        audit)  COMPREPLY=( \$(compgen -W "--last --event --agent --since" -- "\${cur}") ) ;;
      esac
      ;;
    hook)
      COMPREPLY=( \$(compgen -W "\${hook_cmds}" -- "\${cur}") )
      ;;
    ci)
      if [[ \${COMP_CWORD} -eq 2 ]]; then
        COMPREPLY=( \$(compgen -W "\${ci_cmds}" -- "\${cur}") )
      fi
      ;;
    policy)
      COMPREPLY=( \$(compgen -W "\${policy_cmds}" -- "\${cur}") )
      ;;
    run|scan)
      COMPREPLY=( \$(compgen -W "--api-key --format --quiet" -- "\${cur}") )
      ;;
    completion)
      COMPREPLY=( \$(compgen -W "bash zsh fish" -- "\${cur}") )
      ;;
  esac
}
complete -F _rafter_completion rafter
`;

const ZSH_COMPLETION = `
# rafter zsh completion
# Add to ~/.zshrc: eval "$(rafter completion zsh)"
#compdef rafter

_rafter() {
  local state
  typeset -A opt_args

  _arguments \\
    '1: :->cmd' \\
    '*: :->args'

  case \$state in
    cmd)
      _values 'command' \\
        'run[Run a security scan via backend]' \\
        'scan[Alias for run]' \\
        'agent[Agent security features]' \\
        'ci[CI/CD integration]' \\
        'hook[Hook handlers]' \\
        'mcp[MCP server]' \\
        'policy[Policy management]' \\
        'completion[Shell completion scripts]'
      ;;
    args)
      case \$words[2] in
        agent)
          _values 'subcommand' \\
            'init[Initialize agent security]' \\
            'scan[Scan for secrets]' \\
            'exec[Execute command with security validation]' \\
            'config[Manage configuration]' \\
            'audit[View audit logs]' \\
            'audit-skill[Audit a skill file]' \\
            'install-hook[Install git pre-commit hook]' \\
            'verify[Health check]' \\
            'status[Status dashboard]'
          ;;
        hook)
          _values 'subcommand' 'pretool[PreToolUse handler]' 'posttool[PostToolUse handler]'
          ;;
        completion)
          _values 'shell' 'bash' 'zsh' 'fish'
          ;;
      esac
      ;;
  esac
}

_rafter
`;

const FISH_COMPLETION = `
# rafter fish completion
# Save to ~/.config/fish/completions/rafter.fish
# Or: rafter completion fish > ~/.config/fish/completions/rafter.fish

complete -c rafter -f
complete -c rafter -n '__fish_use_subcommand' -a 'run' -d 'Run a security scan via backend'
complete -c rafter -n '__fish_use_subcommand' -a 'agent' -d 'Agent security features'
complete -c rafter -n '__fish_use_subcommand' -a 'ci' -d 'CI/CD integration'
complete -c rafter -n '__fish_use_subcommand' -a 'hook' -d 'Hook handlers'
complete -c rafter -n '__fish_use_subcommand' -a 'mcp' -d 'MCP server'
complete -c rafter -n '__fish_use_subcommand' -a 'completion' -d 'Shell completion scripts'

# agent subcommands
complete -c rafter -n '__fish_seen_subcommand_from agent' -a 'init scan exec config audit audit-skill install-hook verify status'
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from scan' -l quiet -s q -d 'Only output if secrets found'
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from scan' -l json -d 'JSON output'
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from scan' -l format -d 'Output format: text, json, sarif'
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from scan' -l staged -d 'Scan staged files'
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from scan' -l engine -d 'Engine: gitleaks, patterns, auto'

# hook subcommands
complete -c rafter -n '__fish_seen_subcommand_from hook' -a 'pretool posttool'

# completion subcommands
complete -c rafter -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
`;

export function createCompletionCommand(): Command {
  return new Command("completion")
    .description("Generate shell completion scripts")
    .argument("<shell>", "Shell type: bash, zsh, or fish")
    .addHelpText("after", `
Examples:
  # bash — add to ~/.bashrc
  eval "$(rafter completion bash)"

  # zsh — add to ~/.zshrc
  eval "$(rafter completion zsh)"

  # fish — save to completions dir
  rafter completion fish > ~/.config/fish/completions/rafter.fish
`)
    .action((shell: string) => {
      switch (shell.toLowerCase()) {
        case "bash":
          process.stdout.write(BASH_COMPLETION.trimStart());
          break;
        case "zsh":
          process.stdout.write(ZSH_COMPLETION.trimStart());
          break;
        case "fish":
          process.stdout.write(FISH_COMPLETION.trimStart());
          break;
        default:
          console.error(`Unknown shell: ${shell}. Supported: bash, zsh, fish`);
          process.exit(1);
      }
    });
}
