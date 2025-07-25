# Rafter CLI Command Spec

## Commands

### rafter run [OPTIONS]
- -k, --api-key TEXT       (or env var or .env)
- -r, --repo TEXT          (default: current repo)
- -b, --branch TEXT        (default: current branch or 'main')
- -f, --format [json|md]   (default: json)
- --skip-interactive       (fire-and-forget)
- --save [PATH]            (save result to file)
- --save-name TEXT         (override default filename)
- -h, --help

### rafter get SCAN_ID [OPTIONS]
- --interactive            (poll until done)
- --format, --save, --save-name (same as above)

### rafter usage
- (no options)

## Notes
- API key can be provided as a flag, env var, or .env file.
- Does not support embedding credentials in repo URLs. 