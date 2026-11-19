from functools import lru_cache

@lru_cache(maxsize=512)
def cached_manifest_names(contents: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in contents.splitlines() if x.strip() and not x.lstrip().startswith("#"))
