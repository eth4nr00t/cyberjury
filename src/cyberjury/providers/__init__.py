"""Model backends behind a single typed interface.

Every model call goes through `Provider.complete`. `factory` builds providers and
`configuration` resolves the base and finder seats from the environment.
"""
