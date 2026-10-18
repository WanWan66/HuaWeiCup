import json
import statistics
import tempfile
import time
import tracemalloc
from pathlib import Path
from .fixtures import Synthetic, samples
from ..detectors.rules import Detector
from ..pipeline.scan import Pipeline
from ..storage.sqlite import Store

def evaluate(detector):
    tracemalloc.start()
    cpu_start, wall_start=time.process_time(),time.perf_counter()
    comparisons={}
    for name,enabled,with_entropy in [("regex_only",False,False),("regex_context",True,False),("full_pipeline",True,True)]:
        current=Detector(detector._key,context_filter=enabled,enable_entropy=with_entropy)
        tp=fp=fn=0
        corpus = samples() if with_entropy else [s for s in samples() if s[0] != "entropy"]
        for _,text,expected in corpus:
            predicted={x.kind for x in current.detect(text,synthetic=True)}
            tp+=len(expected & predicted);fp+=len(predicted-expected);fn+=len(expected-predicted)
        precision=tp/(tp+fp) if tp+fp else 0
        recall=tp/(tp+fn) if tp+fn else 0
        comparisons[name]={"documents":len(corpus),"TP":tp,"FP":fp,"FN":fn,"Precision":precision,"Recall":recall,
                          "F1":2*precision*recall/(precision+recall) if precision+recall else 0}
    Path("runtime/eval-tmp").mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(dir="runtime/eval-tmp") as folder:
        store=Store(Path(folder)/"evaluation.db")
        source=Synthetic()
        pipeline=Pipeline(store,detector,[source])
        first=pipeline.scan(source,"demo")
        full=[pipeline.scan(source,"demo",full=True) for _ in range(5)]
        incremental=[pipeline.scan(source,"demo") for _ in range(5)]
        alerts=store.snapshot()["alerts"]
        collection=[a["collection_delay_ms"] for a in alerts if a["collection_delay_ms"] is not None]
        alerting=[a["alert_delay_ms"] for a in alerts if a["alert_delay_ms"] is not None]
    wall=time.perf_counter()-wall_start
    cpu=time.process_time()-cpu_start
    current,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
    rss, peak_rss = None, None
    if __import__("os").name == "nt":
        try:
            import ctypes
            from ctypes import wintypes
            class MemoryCounters(ctypes.Structure):
                _fields_ = [("cb",wintypes.DWORD),("PageFaultCount",wintypes.DWORD),
                    ("PeakWorkingSetSize",ctypes.c_size_t),("WorkingSetSize",ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage",ctypes.c_size_t),("QuotaPagedPoolUsage",ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage",ctypes.c_size_t),("QuotaNonPagedPoolUsage",ctypes.c_size_t),
                    ("PagefileUsage",ctypes.c_size_t),("PeakPagefileUsage",ctypes.c_size_t)]
            kernel = ctypes.WinDLL("kernel32",use_last_error=True)
            kernel.GetCurrentProcess.restype = wintypes.HANDLE
            psapi = ctypes.WinDLL("psapi",use_last_error=True)
            psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE,ctypes.POINTER(MemoryCounters),wintypes.DWORD]
            counters=MemoryCounters();counters.cb=ctypes.sizeof(counters)
            if psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(),ctypes.byref(counters),counters.cb):
                rss,peak_rss=counters.WorkingSetSize,counters.PeakWorkingSetSize
        except (OSError, AttributeError):
            pass
    return {
        "dataset":{"documents":len(samples()),"positive_documents":sum(bool(e) for _,_,e in samples()),
                   "negative_documents":sum(not e for _,_,e in samples()),
                   "input_bytes":sum(len(t.encode()) for _,t,_ in samples()),
                   "ground_truth":"controlled synthetic type-level labels; not an external test set"},
        "classification":comparisons,
        "scanning":{"initial":first,
                    "full_repeat":{"runs":5,"documents":sum(r["documents"] for r in full),
                                   "median_ms":statistics.median(r["elapsed_ms"] for r in full)},
                    "incremental_repeat":{"runs":5,"documents":sum(r["documents"] for r in incremental),
                                          "median_ms":statistics.median(r["elapsed_ms"] for r in incremental)}},
        "latency":{"clock":"single Windows wall clock, controlled synthetic publication",
                   "collection_mean_ms":statistics.mean(collection) if collection else None,
                   "scan_to_local_alert_mean_ms":statistics.mean(alerting) if alerting else None,
                   "published_to_local_alert_mean_ms":statistics.mean(
                       ( __import__("datetime").datetime.fromisoformat(a["alerted_at"])-
                         __import__("datetime").datetime.fromisoformat(a["published_at"]) ).total_seconds()*1000
                       for a in alerts) if alerts else None,
                   "real_source_discovery_latency":None},
        "resources":{"wall_seconds":wall,"process_cpu_seconds":cpu,
                     "process_cpu_percent_one_core_equivalent":cpu/wall*100 if wall else None,
                     "python_tracemalloc_peak_bytes":peak,"process_rss_bytes":rss,"process_peak_rss_bytes":peak_rss,
                     "scope":"evaluation process only; tracemalloc is not RSS"},
    }
