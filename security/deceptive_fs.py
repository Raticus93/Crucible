"""
Crucible deceptive filesystem builder.

Generates fake environment files that look real to code probing the container.
Used in Deceptive mode to create a convincing honeypot filesystem.

All fake files are injected via put_archive alongside solution.py.
They appear at realistic paths inside the container (/root/.env, /root/.config/...).
"""

from typing import Dict

from security.canary import generate_canary_credentials


def build_deceptive_artifacts(base_artifacts: Dict[str, str] = None) -> Dict[str, str]:
    """
    Return a dict of {filepath: content} that looks like a real developer's home dir.
    Designed to be injected into the sandbox via put_archive alongside solution.py.

    The paths are relative to /workspace; the sandbox will see them under that root.
    For root-path spoofing, inject separately if needed (put_archive to /).
    """
    canary = generate_canary_credentials()
    artifacts = dict(base_artifacts or {})

    # Fake .env file at /workspace/.env (will be found by python-dotenv)
    env_lines = ["# Environment configuration\n"]
    for key, value in canary.items():
        env_lines.append(f"{key}={value}\n")
    artifacts[".env"] = "".join(env_lines)

    # Fake .private.env (pattern used by this project)
    artifacts[".private.env"] = (
        f"ANTHROPIC_API_KEY={canary['ANTHROPIC_API_KEY']}\n"
        f"OPENAI_API_KEY={canary['OPENAI_API_KEY']}\n"
    )

    # Fake config file
    artifacts[".crucible_config"] = (
        f"[credentials]\n"
        f"api_key = {canary['OPENAI_API_KEY']}\n"
        f"anthropic_key = {canary['ANTHROPIC_API_KEY']}\n"
        f"github_token = {canary['GITHUB_TOKEN']}\n"
    )

    # Fake git config (attackers sometimes read this for tokens)
    artifacts[".gitconfig"] = (
        "[user]\n"
        "  name = Developer\n"
        "  email = dev@example.com\n"
        "[credential]\n"
        f"  helper = store\n"
    )

    # Fake credential store
    artifacts[".git-credentials"] = (
        f"https://oauth2:{canary['GITHUB_TOKEN']}@github.com\n"
    )

    return artifacts


def deceptive_env_vars(real_env_vars: Dict[str, str] = None) -> Dict[str, str]:
    """
    Return environment variables for the container that use canary values
    instead of real credentials.

    NEVER call this with real credentials — it returns a clean canary set.
    """
    return generate_canary_credentials()


def rich_os_env_vars(hostname: str = "dev-workstation-01", username: str = "developer") -> Dict[str, str]:
    """
    Return realistic OS-level environment variables that make the container
    look like a genuine developer's Linux machine rather than a bare Docker box.

    A payload probing os.environ for signs of virtualisation will find nothing
    unusual here. The values are static and non-sensitive.
    """
    return {
        "USER": username,
        "LOGNAME": username,
        "HOME": f"/home/{username}",
        "HOSTNAME": hostname,
        "SHELL": "/bin/bash",
        "TERM": "xterm-256color",
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "PWD": f"/home/{username}/projects",
        "OLDPWD": f"/home/{username}",
        "EDITOR": "vim",
        "VISUAL": "vim",
        "PAGER": "less",
        "COLORTERM": "truecolor",
        # Make it look like a real Python dev environment
        "VIRTUAL_ENV": f"/home/{username}/.venv",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
    }
