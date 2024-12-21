"""Check that basic features work.

Catch cases where e.g. files are missing so the import doesn't work. It is
recommended to check that e.g. assets are included.
"""

import uv_secure


print(uv_secure.__version__)
