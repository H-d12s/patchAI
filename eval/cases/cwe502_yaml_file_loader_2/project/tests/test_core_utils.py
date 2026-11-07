from core_utils import PipelineFile


def test_loads_a_file(tmp_path):
    path = tmp_path / "spec.yaml"
    path.write_text("steps:\n  - build\n  - test\n")
    assert PipelineFile(str(path)).load() == {"steps": ["build", "test"]}
