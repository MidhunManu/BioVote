import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / '.env'


def load_env_file() -> None:
  if not ENV_FILE.exists():
    return

  for raw_line in ENV_FILE.read_text(encoding='utf-8').splitlines():
    line = raw_line.strip()
    if not line or line.startswith('#') or '=' not in line:
      continue

    key, value = line.split('=', 1)
    key = key.strip()
    value = value.strip()

    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
      value = value[1:-1]

    os.environ.setdefault(key, value)


load_env_file()
