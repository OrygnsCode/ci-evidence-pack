try:
    from importlib.metadata import version
    __version__ = version("ci-evidence-pack")
except ImportError:
    __version__ = "unknown"
