import { Command } from "commander";

const BASH_COMPLETION = `# rafter bash completion
_rafter_completions() {
  local cur prev commands
  COMPREPLY=()
  cur="\${COMP_WORDS[COMP_CWORD]}"
  prev="\${COMP_WORDS[COMP_CWORD-1]}"

  # Top-level commands
  commands="run scan get usage agent ci hook mcp policy completion help"

  case "\${prev}" in
    rafter)
      COMPREPLY=( $(compgen -W "\${commands} --agent --version --help" -- "\${cur}") )
      return 0
      ;;
    agent)
      COMPREPLY=( $(compgen -W "scan init audit config exec audit-skill install-hook verify status update-gitleaks baseline --help" -- "\${cur}") )
      return 0
      ;;
    config)
      if [[ "\${COMP_WORDS[1]}" == "agent" ]]; then
        COMPREPLY=( $(compgen -W "show get set --help" -- "\${cur}") )
      fi
      return 0
      ;;
    ci)
      COMPREPLY=( $(compgen -W "init --help" -- "\${cur}") )
      return 0
      ;;
    hook)
      COMPREPLY=( $(compgen -W "pretool --help" -- "\${cur}") )
      return 0
      ;;
    mcp)
      COMPREPLY=( $(compgen -W "serve --help" -- "\${cur}") )
      return 0
      ;;
    policy)
      COMPREPLY=( $(compgen -W "export --help" -- "\${cur}") )
      return 0
      ;;
    completion)
      COMPREPLY=( $(compgen -W "bash zsh fish" -- "\${cur}") )
      return 0
      ;;
    scan)
      if [[ "\${COMP_WORDS[1]}" == "agent" ]]; then
        COMPREPLY=( $(compgen -W "--quiet --json --staged --diff --engine --help" -- "\${cur}") )
      else
        COMPREPLY=( $(compgen -W "--repo --branch --api-key --format --skip-interactive --quiet --help" -- "\${cur}") )
      fi
      return 0
      ;;
    run)
      COMPREPLY=( $(compgen -W "--repo --branch --api-key --format --skip-interactive --quiet --help" -- "\${cur}") )
      return 0
      ;;
    get)
      COMPREPLY=( $(compgen -W "--api-key --format --interactive --quiet --help" -- "\${cur}") )
      return 0
      ;;
    init)
      if [[ "\${COMP_WORDS[1]}" == "agent" ]]; then
        COMPREPLY=( $(compgen -W "--risk-level --skip-openclaw --skip-claude-code --claude-code --skip-gitleaks --help" -- "\${cur}") )
      elif [[ "\${COMP_WORDS[1]}" == "ci" ]]; then
        COMPREPLY=( $(compgen -W "--platform --output --with-backend --help" -- "\${cur}") )
      fi
      return 0
      ;;
  esac
}
complete -F _rafter_completions rafter
`;

const ZSH_COMPLETION = `#compdef rafter

_rafter() {
  local -a commands
  commands=(
    'run:Submit a security scan to the Rafter backend'
    'scan:Alias for run'
    'get:Retrieve scan results'
    'usage:Check API usage quota'
    'agent:Agent security commands'
    'ci:CI/CD pipeline setup'
    'hook:Git hook handlers'
    'mcp:MCP server'
    'policy:Policy management'
    'completion:Generate shell completions'
    'help:Display help'
  )

  local -a agent_commands
  agent_commands=(
    'scan:Scan files for secrets locally'
    'init:Initialize agent security'
    'audit:View audit log'
    'config:Manage configuration'
    'exec:Execute command with security'
    'audit-skill:Audit a Claude Code skill'
    'install-hook:Install git hook (pre-commit or pre-push)'
    'verify:Check integration status'
    'status:Show agent status'
    'update-gitleaks:Update gitleaks binary'
    'baseline:Manage findings baseline'
  )

  local -a config_commands
  config_commands=(
    'show:Show current configuration'
    'get:Get a configuration value'
    'set:Set a configuration value'
  )

  _arguments -C \\
    '(-a --agent)'{-a,--agent}'[Plain output for AI agents]' \\
    '(-V --version)'{-V,--version}'[Show version]' \\
    '(-h --help)'{-h,--help}'[Show help]' \\
    '1:command:->command' \\
    '*::arg:->args'

  case "\$state" in
    command)
      _describe 'command' commands
      ;;
    args)
      case "\$words[1]" in
        agent)
          _arguments -C \\
            '1:subcommand:->subcmd' \\
            '*::arg:->subargs'
          case "\$state" in
            subcmd)
              _describe 'agent command' agent_commands
              ;;
            subargs)
              case "\$words[1]" in
                scan)
                  _arguments \\
                    '(-q --quiet)'{-q,--quiet}'[Only output if secrets found]' \\
                    '--json[Output as JSON]' \\
                    '--staged[Scan only staged files]' \\
                    '--diff[Scan files changed since ref]:ref:' \\
                    '--engine[Scanner engine]:engine:(gitleaks patterns)' \\
                    '1:path:_files'
                  ;;
                init)
                  _arguments \\
                    '--risk-level[Risk level]:level:(minimal moderate aggressive)' \\
                    '--skip-openclaw[Skip OpenClaw installation]' \\
                    '--skip-claude-code[Skip Claude Code installation]' \\
                    '--claude-code[Force Claude Code installation]' \\
                    '--skip-gitleaks[Skip Gitleaks download]'
                  ;;
                audit)
                  _arguments \\
                    '--last[Show last N entries]:count:' \\
                    '--event[Filter by event type]:type:' \\
                    '--agent[Filter by agent type]:agent:(openclaw claude-code)' \\
                    '--since[Show entries since date]:date:'
                  ;;
                config)
                  _arguments -C '1:subcommand:->cfgcmd'
                  case "\$state" in
                    cfgcmd)
                      _describe 'config command' config_commands
                      ;;
                  esac
                  ;;
                exec)
                  _arguments \\
                    '--skip-scan[Skip pre-execution scanning]' \\
                    '--force[Skip approval prompts]' \\
                    '1:command:'
                  ;;
                audit-skill)
                  _arguments \\
                    '--skip-openclaw[Skip OpenClaw integration]' \\
                    '--json[Output as JSON]' \\
                    '1:skill-path:_files'
                  ;;
                install-hook)
                  _arguments \\
                    '--global[Install globally]'
                  ;;
              esac
              ;;
          esac
          ;;
        run|scan)
          _arguments \\
            '(-r --repo)'{-r,--repo}'[Repository]:repo:' \\
            '(-b --branch)'{-b,--branch}'[Branch]:branch:' \\
            '(-k --api-key)'{-k,--api-key}'[API key]:key:' \\
            '(-f --format)'{-f,--format}'[Output format]:format:(json md)' \\
            '--skip-interactive[Do not wait for scan]' \\
            '--quiet[Suppress status messages]'
          ;;
        get)
          _arguments \\
            '(-k --api-key)'{-k,--api-key}'[API key]:key:' \\
            '(-f --format)'{-f,--format}'[Output format]:format:(json md)' \\
            '--interactive[Poll until done]' \\
            '--quiet[Suppress status messages]' \\
            '1:scan_id:'
          ;;
        usage)
          _arguments \\
            '(-k --api-key)'{-k,--api-key}'[API key]:key:'
          ;;
        ci)
          _arguments -C '1:subcommand:(init)'
          ;;
        hook)
          _arguments -C '1:subcommand:(pretool)'
          ;;
        mcp)
          _arguments -C '1:subcommand:(serve)'
          ;;
        policy)
          _arguments -C \\
            '1:subcommand:(export)' \\
            '*::arg:->policyargs'
          case "\$state" in
            policyargs)
              _arguments \\
                '--format[Target format]:format:(claude codex)' \\
                '--output[Output file]:path:_files'
              ;;
          esac
          ;;
        completion)
          _arguments '1:shell:(bash zsh fish)'
          ;;
      esac
      ;;
  esac
}

_rafter
`;

const FISH_COMPLETION = `# rafter fish completion

# Disable file completions by default
complete -c rafter -f

# Global options
complete -c rafter -s a -l agent -d 'Plain output for AI agents'
complete -c rafter -s V -l version -d 'Show version'
complete -c rafter -s h -l help -d 'Show help'

# Top-level commands
complete -c rafter -n '__fish_use_subcommand' -a run -d 'Submit a security scan'
complete -c rafter -n '__fish_use_subcommand' -a scan -d 'Alias for run'
complete -c rafter -n '__fish_use_subcommand' -a get -d 'Retrieve scan results'
complete -c rafter -n '__fish_use_subcommand' -a usage -d 'Check API usage quota'
complete -c rafter -n '__fish_use_subcommand' -a agent -d 'Agent security commands'
complete -c rafter -n '__fish_use_subcommand' -a ci -d 'CI/CD pipeline setup'
complete -c rafter -n '__fish_use_subcommand' -a hook -d 'Git hook handlers'
complete -c rafter -n '__fish_use_subcommand' -a mcp -d 'MCP server'
complete -c rafter -n '__fish_use_subcommand' -a policy -d 'Policy management'
complete -c rafter -n '__fish_use_subcommand' -a completion -d 'Generate shell completions'

# run / scan options
complete -c rafter -n '__fish_seen_subcommand_from run scan' -s r -l repo -d 'Repository (org/repo)' -r
complete -c rafter -n '__fish_seen_subcommand_from run scan' -s b -l branch -d 'Branch' -r
complete -c rafter -n '__fish_seen_subcommand_from run scan' -s k -l api-key -d 'API key' -r
complete -c rafter -n '__fish_seen_subcommand_from run scan' -s f -l format -d 'Output format' -ra 'json md'
complete -c rafter -n '__fish_seen_subcommand_from run scan' -l skip-interactive -d 'Do not wait for scan'
complete -c rafter -n '__fish_seen_subcommand_from run scan' -l quiet -d 'Suppress status messages'

# get options
complete -c rafter -n '__fish_seen_subcommand_from get' -s k -l api-key -d 'API key' -r
complete -c rafter -n '__fish_seen_subcommand_from get' -s f -l format -d 'Output format' -ra 'json md'
complete -c rafter -n '__fish_seen_subcommand_from get' -l interactive -d 'Poll until done'
complete -c rafter -n '__fish_seen_subcommand_from get' -l quiet -d 'Suppress status messages'

# usage options
complete -c rafter -n '__fish_seen_subcommand_from usage' -s k -l api-key -d 'API key' -r

# agent subcommands
complete -c rafter -n '__fish_seen_subcommand_from agent; and not __fish_seen_subcommand_from scan init audit config exec audit-skill install-hook verify status update-gitleaks baseline' -a scan -d 'Scan files for secrets'
complete -c rafter -n '__fish_seen_subcommand_from agent; and not __fish_seen_subcommand_from scan init audit config exec audit-skill install-hook verify status update-gitleaks baseline' -a init -d 'Initialize agent security'
complete -c rafter -n '__fish_seen_subcommand_from agent; and not __fish_seen_subcommand_from scan init audit config exec audit-skill install-hook verify status update-gitleaks baseline' -a audit -d 'View audit log'
complete -c rafter -n '__fish_seen_subcommand_from agent; and not __fish_seen_subcommand_from scan init audit config exec audit-skill install-hook verify status update-gitleaks baseline' -a config -d 'Manage configuration'
complete -c rafter -n '__fish_seen_subcommand_from agent; and not __fish_seen_subcommand_from scan init audit config exec audit-skill install-hook verify status update-gitleaks baseline' -a exec -d 'Execute with security'
complete -c rafter -n '__fish_seen_subcommand_from agent; and not __fish_seen_subcommand_from scan init audit config exec audit-skill install-hook verify status update-gitleaks baseline' -a audit-skill -d 'Audit a skill file'
complete -c rafter -n '__fish_seen_subcommand_from agent; and not __fish_seen_subcommand_from scan init audit config exec audit-skill install-hook verify status update-gitleaks baseline' -a install-hook -d 'Install pre-commit hook'
complete -c rafter -n '__fish_seen_subcommand_from agent; and not __fish_seen_subcommand_from scan init audit config exec audit-skill install-hook verify status update-gitleaks baseline' -a verify -d 'Check integration status'

# agent scan options
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from scan' -s q -l quiet -d 'Only output if secrets found'
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from scan' -l json -d 'Output as JSON'
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from scan' -l staged -d 'Scan only staged files'
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from scan' -l diff -d 'Scan changed since ref' -r
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from scan' -l engine -d 'Scanner engine' -ra 'gitleaks patterns'

# agent init options
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from init' -l risk-level -d 'Risk level' -ra 'minimal moderate aggressive'
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from init' -l skip-openclaw -d 'Skip OpenClaw'
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from init' -l skip-claude-code -d 'Skip Claude Code'
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from init' -l claude-code -d 'Force Claude Code'
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from init' -l skip-gitleaks -d 'Skip Gitleaks'

# agent audit options
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from audit' -l last -d 'Show last N entries' -r
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from audit' -l event -d 'Filter by event type' -r
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from audit' -l agent -d 'Filter by agent type' -ra 'openclaw claude-code'
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from audit' -l since -d 'Since date' -r

# agent config subcommands
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from config' -a show -d 'Show configuration'
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from config' -a get -d 'Get a config value'
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from config' -a set -d 'Set a config value'

# agent exec options
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from exec' -l skip-scan -d 'Skip pre-execution scanning'
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from exec' -l force -d 'Skip approval prompts'

# agent audit-skill options
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from audit-skill' -l skip-openclaw -d 'Skip OpenClaw integration'
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from audit-skill' -l json -d 'Output as JSON'

# agent install-hook options
complete -c rafter -n '__fish_seen_subcommand_from agent; and __fish_seen_subcommand_from install-hook' -l global -d 'Install globally'

# ci subcommands
complete -c rafter -n '__fish_seen_subcommand_from ci' -a init -d 'Initialize CI pipeline'
complete -c rafter -n '__fish_seen_subcommand_from ci; and __fish_seen_subcommand_from init' -l platform -d 'CI platform' -ra 'github gitlab circleci'
complete -c rafter -n '__fish_seen_subcommand_from ci; and __fish_seen_subcommand_from init' -l output -d 'Output path' -r
complete -c rafter -n '__fish_seen_subcommand_from ci; and __fish_seen_subcommand_from init' -l with-backend -d 'Include backend audit'

# hook subcommands
complete -c rafter -n '__fish_seen_subcommand_from hook' -a pretool -d 'PreToolUse hook handler'

# mcp subcommands
complete -c rafter -n '__fish_seen_subcommand_from mcp' -a serve -d 'Start MCP server'
complete -c rafter -n '__fish_seen_subcommand_from mcp; and __fish_seen_subcommand_from serve' -l transport -d 'Transport type' -r

# policy subcommands
complete -c rafter -n '__fish_seen_subcommand_from policy' -a export -d 'Export policy'
complete -c rafter -n '__fish_seen_subcommand_from policy; and __fish_seen_subcommand_from export' -l format -d 'Target format' -ra 'claude codex'
complete -c rafter -n '__fish_seen_subcommand_from policy; and __fish_seen_subcommand_from export' -l output -d 'Output file' -r

# completion subcommand
complete -c rafter -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish' -d 'Shell type'
`;

export function createCompletionCommand(): Command {
  return new Command("completion")
    .description("Generate shell completion scripts")
    .argument("<shell>", "Shell type: bash, zsh, or fish")
    .action((shell: string) => {
      switch (shell) {
        case "bash":
          process.stdout.write(BASH_COMPLETION);
          break;
        case "zsh":
          process.stdout.write(ZSH_COMPLETION);
          break;
        case "fish":
          process.stdout.write(FISH_COMPLETION);
          break;
        default:
          process.stderr.write(
            `Unknown shell: ${shell}. Supported: bash, zsh, fish\n`,
          );
          process.exit(1);
      }
    });
}
