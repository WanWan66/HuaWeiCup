def test_evaluation_produces_measured_metrics(detector,monkeypatch,tmp_path):
    from secretradar.evaluation.run import evaluate
    monkeypatch.chdir(tmp_path)
    data=evaluate(detector)
    assert data["classification"]["full_pipeline"]["TP"]==7
    assert data["classification"]["full_pipeline"]["FP"]==0
    assert data["classification"]["full_pipeline"]["FN"]==0
    assert data["scanning"]["full_repeat"]["documents"]==70
    assert data["scanning"]["incremental_repeat"]["documents"]==0
    assert data["resources"]["python_tracemalloc_peak_bytes"]>0
