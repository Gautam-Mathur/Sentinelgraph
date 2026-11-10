from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from app.domain.scoring import render_scoring_model_markdown  # noqa: E402


def main() -> None:
    output = ROOT.parent / "docs" / "scoring-model.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_scoring_model_markdown(), encoding="utf-8")
    print(f"Updated {output}")


if __name__ == "__main__":
    main()
