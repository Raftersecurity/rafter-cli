"""rf-7dda: the python hook path must not load a cwd .env, so a repo .env cannot
disable the hook the way an unguarded dotenv can in Node. If cwd-dotenv loading
is ever added to the hook path, the first test goes red. The second is the
positive control: the disable check can still see a REAL env var."""
import os
import tempfile

from rafter_cli.core.hook_control import resolve_hook_control


def test_cwd_dotenv_does_not_disable_hook():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, ".env"), "w") as f:
            f.write("RAFTER_DISABLE_HOOKS=1\nRAFTER_DISABLE_SECRET_SCAN=1\n")
        cwd0 = os.getcwd()
        try:
            os.chdir(d)
            env = {k: v for k, v in os.environ.items() if not k.startswith("RAFTER_DISABLE")}
            hc = resolve_hook_control(config=None, env=env)
            assert hc.hook_enabled is True
        finally:
            os.chdir(cwd0)


def test_real_env_var_still_disables():
    hc = resolve_hook_control(config=None, env={"RAFTER_DISABLE_HOOKS": "1"})
    assert hc.hook_enabled is False
