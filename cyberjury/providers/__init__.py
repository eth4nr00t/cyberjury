"""Model backends behind a single typed interface.

Agents never call a vendor SDK directly, they call a Provider. This keeps the
"any model" axis independent from the rest of the framework.
"""
