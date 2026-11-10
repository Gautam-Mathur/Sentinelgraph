import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND_ROOT))

from app.domain.scoring import render_scoring_model_markdown  # noqa: E402


def main() -> None:
    output = REPO_ROOT / "docs" / "scoring-model.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_scoring_model_markdown(), encoding="utf-8")
    print(f"Updated {output}")


if __name__ == "__main__":
    main()
