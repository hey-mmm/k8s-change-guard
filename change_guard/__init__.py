"""k8s-change-guard evaluation kernel.

The publicly owned surface is deliberately small:

* :func:`change_guard.engine.evaluate` evaluates rendered Kubernetes objects.
* :func:`change_guard.renderer.render_tree` renders the permitted subset of a
  candidate tree inside a restrictive bubblewrap sandbox.
* :func:`change_guard.evidence.collect` gathers read-only Kubernetes and
  Prometheus evidence.
* :func:`change_guard.ai.analyze` performs trusted-runbook-assisted review.

The daemon, GitHub integration, and post-deploy verifier live outside this
package and import these functions.
"""

from __future__ import annotations

from .engine import RULE_VERSION, evaluate
from .renderer import RenderError, load_rendered_manifests, render_tree

__all__ = [
    "RULE_VERSION",
    "RenderError",
    "evaluate",
    "load_rendered_manifests",
    "render_tree",
]

__version__ = "0.2.0"
