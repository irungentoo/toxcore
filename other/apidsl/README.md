This folder contains the input file (``tox.in.h``) that has to be used to generate the ``tox.h`` api with: https://github.com/iphydf/apidsl

# Minimal requirements

There are some minimal requirements to contribute to ``tox.h``:
* unix environment
* ``astyle`` ``>=2.03``
* [``apidsl``](https://github.com/iphydf/apidsl) (you can use provided service with curl instead)

## Quick way

If you want to do it quickly and you don't have time for anything other than copypasting commands, you should have ``curl`` installed.


1. Make sure that you have ``curl`` and ``>=astyle-2.03`` installed
2. Modify [``tox.in.h``](/other/apidsl/tox.in.h)
3. Run command below ↓

Command to run from ``toxcore`` directory (quick way, involves using curl):
```bash
rm toxcore/tox.h && \
( curl -X POST --data-binary @- https://criticism.herokuapp.com/apidsl < ./other/apidsl/tox.in.h > ./toxcore/tox.h ) && \
astyle --options=./other/astyle/astylerc ./toxcore/tox.h
```

When formatting will be complete, you should see output like:
```
Formatted  ./toxcore/tox.h
```

You may want to make sure with ``git diff`` that changes made in ``tox.h`` reflect changes in ``tox.in.h``.

And you're done.


## Manually

If you prefer to have more control over what is happening, there are steps below:

1. Install [``apidsl``](https://github.com/iphydf/apidsl)
2. Install ``astyle``, version 2.03 or later.
3. Modify [``tox.in.h``](/other/apidsl/tox.in.h)
4. Use ``apidsl`` ``??``
5. Parse generated ``tox.h`` with astyle, minimal command for it would be:
```bash
astyle --options=./other/astyle/astylerc ./toxcore/tox.h
```

**Always pass output from ``apidsl`` through astyle.**