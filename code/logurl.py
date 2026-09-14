from mitmproxy import ctx, http

def request(flow: http.HTTPFlow) -> None:
    ctx.log.info("REQ %s %s" % (flow.request.method, flow.request.pretty_url))

def response(flow: http.HTTPFlow) -> None:
    ct = flow.response.headers.get("Content-Type", "") if flow.response else ""
    body = flow.response.get_text() if flow.response else ""
    if body:
        ctx.log.info("RESP %s [%s] %s" % (flow.response.status_code, ct, body[:500].replace("\n", " ")))
