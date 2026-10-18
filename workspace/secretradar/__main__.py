import argparse
import json
import os
from pathlib import Path
from .detectors.rules import Detector
from .model import SourceError
from .pipeline.scan import Pipeline
from .storage.sqlite import Store
from .sources.registry import configured
from .evaluation.fixtures import Synthetic

def main():
    p=argparse.ArgumentParser(description="Authorized-source credential review; no online validity probing")
    p.add_argument("command",choices=["demo","scan","scan-one","watch","serve","evaluate","events","alert-state","locate"])
    p.add_argument("--config",default="config.example.json");p.add_argument("--db",default="runtime/secretradar.db")
    p.add_argument("--mode",choices=["demo","real"],default="real");p.add_argument("--port",type=int,default=8765)
    p.add_argument("--output",default="runtime/evaluation.json");p.add_argument("--source")
    p.add_argument("--full",action="store_true");p.add_argument("--interval",type=float,default=60)
    p.add_argument("--timeout",type=float,default=30);p.add_argument("--max-polls",type=int)
    p.add_argument("--stop-file");p.add_argument("--event-log");p.add_argument("--alert-id",type=int);p.add_argument("--state",choices=["open","acknowledged","resolved"])
    p.add_argument("--path-id");p.add_argument("--operator-local",action="store_true");p.add_argument("--open-editor",action="store_true")
    args=p.parse_args()
    raw=os.environ.get("SECRETRADAR_HMAC_KEY","")
    if len(raw.encode())<32:p.exit(2,"SECRETRADAR_HMAC_KEY must contain at least 32 UTF-8 bytes; no default key.\n")
    detector=Detector(raw.encode());result=None
    try:
        if args.command=="evaluate":
            from .evaluation.run import evaluate
            result=evaluate(detector);Path(args.output).parent.mkdir(parents=True,exist_ok=True)
            Path(args.output).write_text(json.dumps(result,indent=2),encoding="utf-8")
        else:
            store=Store(args.db)
            if args.command=="serve":
                import uvicorn
                from .api.app import create_app
                uvicorn.run(create_app(store,args.mode),host="127.0.0.1",port=args.port,access_log=False);return
            if args.command=="events":
                if not args.event_log:raise SourceError("event_log_required")
                result={"events":store.export_events(args.event_log)}
            elif args.command=="alert-state":
                if args.alert_id is None or args.state is None:raise SourceError("alert_id_and_state_required")
                store.lifecycle(args.alert_id,args.state);result={"updated":True,"alert_id":args.alert_id,"state":args.state}
            elif args.command=="watch":
                from .pipeline.watch import watch
                if args.max_polls is not None and args.max_polls<1:raise SourceError("max_polls_invalid")
                result=watch(args.config,store,args.interval,args.timeout,args.max_polls,args.event_log,stop_file=args.stop_file)
            else:
                sources=[Synthetic()] if args.command=="demo" else configured(args.config)
                if args.command in {"scan-one","locate"}:
                    sources=[s for s in sources if s.source_id==args.source]
                    if len(sources)!=1:raise SourceError("source_not_allowed")
                pipeline=Pipeline(store,detector,sources)
                if args.command=="locate":
                    if not args.operator_local or not args.path_id:raise SourceError("operator_local_and_path_id_required")
                    from .pipeline.locator import locate
                    locate(sources[0],detector,args.path_id,args.open_editor)
                    result={"located":True,"source_id":args.source,"path_id":args.path_id,"editor_opened":args.open_editor}
                else:
                    mode="demo" if args.command=="demo" else json.loads(Path(args.config).read_text(encoding="utf-8")).get("mode",args.mode)
                    scans=[pipeline.scan(s,mode,args.full) for s in sources]
                    if args.event_log:store.export_events(args.event_log)
                    result=scans[0] if args.command=="scan-one" else {"mode":mode,"results":scans}
                    print(json.dumps(result))
                    if any(s["status"]=="error" for s in scans):raise SystemExit(1)
                    return
        print(json.dumps(result))
    except SourceError as exc:
        print(json.dumps({"status":"busy" if exc.code=="source_busy" else "error","error_code":exc.code,"retry_after":exc.retry_after}))
        raise SystemExit(2) from None
    except (OSError,ValueError,KeyError,TypeError):
        print(json.dumps({"status":"error","error_code":"operation_failed"}));raise SystemExit(2) from None
if __name__=="__main__":main()
