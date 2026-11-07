from handlers_utils import WorkflowSpec


def test_loads_a_file(tmp_path):
    path = tmp_path / "spec.yaml"
    path.write_text("steps:\n  - build\n  - test\n")
    assert WorkflowSpec(str(path)).load() == {"steps": ["build", "test"]}
