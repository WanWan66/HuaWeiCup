import json
from html import escape
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

def create_app(store, mode="real"):
    app = FastAPI(title="SecretRadar", docs_url=None, redoc_url=None, openapi_url=None)
    def recorded_mode():
        with store.connect() as db:
            modes = {row[0] for row in db.execute("SELECT DISTINCT mode FROM jobs")}
        return next(iter(modes)) if len(modes) == 1 else ("mixed" if modes else mode)
    @app.get("/health")
    def health():
        return {"status":"ok","mode":recorded_mode(),"credential_validity":"never_validated"}
    @app.get("/api/dashboard")
    def dashboard():
        return {"mode":recorded_mode(), **store.snapshot()}
    @app.get("/", response_class=HTMLResponse)
    def index():
        data=store.snapshot()
        def table(rows, columns):
            head="".join("<th>"+escape(c)+"</th>" for c in columns)
            body="".join("<tr>"+"".join("<td>"+escape(str(r.get(c) if r.get(c) is not None else "unavailable"))+"</td>" for c in columns)+"</tr>" for r in rows)
            return "<div class='scroll'><table><thead><tr>"+head+"</tr></thead><tbody>"+body+"</tbody></table></div>"
        template=(Path(__file__).parents[1]/"dashboard"/"index.html").read_text(encoding="utf-8")
        parts={
            "MODE": {"demo":"受控合成演示 / DEMO","real":"授权来源 / REAL","mixed":"混合数据 / MIXED（含演示记录）"}[recorded_mode()],
            "METRICS":escape(json.dumps(data["metrics"],ensure_ascii=False)),
            "SOURCES":table(data["sources"],["source_id","source_type","status","error_code","failures","next_retry_at","updated_at"]),
            "JOBS":table(data["jobs"],["id","source_id","mode","status","documents","skipped","candidates","new_alerts","elapsed_ms","rule_version"]),
            "TYPES":table(data["by_type"],["kind","count"]),
            "ALERTS":table(data["alerts"],["id","source_id","path","kind","classification","severity","masked","line","state","occurrences","first_job_id","last_job_id","rule_version","reason"]),
            "TIMES":table(data["alerts"],["id","content_created_at","accessible_at","published_at","first_seen_at","scan_completed_at","alerted_at","persisted_at"]),
        }
        for key,value in parts.items():
            template=template.replace("{{"+key+"}}",value)
        return template
    return app
