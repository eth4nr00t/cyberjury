"""Model backends behind a single typed interface.

Every model call goes through `Provider.complete`. `factory` builds providers and
`configuration` resolves the finder, skeptic, and confirmer seats from the environment.
"""
