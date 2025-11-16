"""Visualization helpers for the IDS dashboard.

This package avoids importing Streamlit at package import time. Call `render_visuals`
by importing the symbol directly from `app.visual.visuals` or via the helper `get_renderer()`.
"""

from typing import Callable


def get_renderer() -> Callable:
		"""Lazily import and return the render_visuals function.

		Usage:
			render_visuals = get_renderer()
			render_visuals(history)
		"""
		from .visuals import render_visuals

		return render_visuals


__all__ = ["get_renderer"]
