"""Opt-in loopback accessibility harness; never installed into the web factory.

Requires an existing disposable hosted configuration and an operator-installed
axe-core/axe.min.js. Uses normal OIDC/session/role checks; adds no test login.
"""
import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit

from starlette.responses import FileResponse, HTMLResponse, Response

from cleartrail.hosted import create_app, STATIC
from cleartrail.hosted_settings import HostedSettings

AUDIT_SCRIPT = """
document.querySelector('#qa-status').textContent='Ready for accessibility audit';
console.log('ClearTrail accessibility harness ready');
document.addEventListener('keydown',event=>{if(event.key==='F8'){event.preventDefault();document.querySelector('#qa-run').click();}});
document.querySelector('#qa-run').addEventListener('click',async event=>{
 const button=event.target, status=document.querySelector('#qa-status'), output=document.querySelector('#qa-results');
 button.disabled=true; status.textContent='Running accessibility audit…'; output.textContent='';
 try {
  const result=await axe.run({exclude:[['#qa-audit-panel']]},{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa','best-practice']}});
  const report={engine:result.testEngine,userAgent:navigator.userAgent,page:location.hash||'#overview',at:result.timestamp,
    violations:result.violations.map(r=>({id:r.id,impact:r.impact,help:r.help,helpUrl:r.helpUrl,nodes:r.nodes.map(n=>({target:n.target,summary:n.failureSummary}))})),
    incomplete:result.incomplete.map(r=>({id:r.id,nodes:r.nodes.map(n=>n.target)})),passed:result.passes.length};
  output.textContent=JSON.stringify(report,null,2);status.textContent='Accessibility audit complete';
 } catch(error){status.textContent='Accessibility audit failed';output.textContent=String(error);}
 finally {button.disabled=false;}
});
"""


def make_harness(settings, axe_path):
    url = urlsplit(settings.public_url)
    if settings.environment == "production" or url.scheme != "http" or url.hostname != "127.0.0.1":
        raise ValueError("QA harness requires disposable, non-production loopback settings.")
    axe_path = Path(axe_path).resolve(strict=True)
    if axe_path.name != "axe.min.js":
        raise ValueError("Choose the pinned axe-core/axe.min.js file.")
    app = create_app(settings)

    @app.get("/qa/page")
    def qa_page():
        addition = '<section id="qa-audit-panel" aria-labelledby="qa-title"><h2 id="qa-title">Local accessibility QA</h2><button id="qa-run" class="button secondary">Run accessibility audit</button><p id="qa-status" role="status"></p><pre id="qa-results" data-testid="a11y-results"></pre></section><script src="/qa/axe.js" defer></script><script src="/qa/audit.js" defer></script>'
        return HTMLResponse((STATIC / "index.html").read_text(encoding="utf-8").replace("</main>", addition + "</main>"))

    @app.get("/qa/axe.js")
    def axe_asset():
        return FileResponse(axe_path, media_type="text/javascript")

    @app.get("/qa/audit.js")
    def audit_script():
        return Response(AUDIT_SCRIPT, media_type="text/javascript")

    return app


def main():
    import uvicorn
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--axe", type=Path, required=True)
    args = parser.parse_args()
    settings = HostedSettings(**json.loads(args.settings.read_text(encoding="utf-8")))
    app = make_harness(settings, args.axe)
    uvicorn.run(app, host="127.0.0.1", port=urlsplit(settings.public_url).port or 80, access_log=False)


if __name__ == "__main__":
    main()
