"""A deliberately vulnerable request handler (benchmark fixture)."""


def handler(req):
    # VULN: untrusted request body passed to eval() => remote code execution.
    return eval(req)  # noqa: S307
