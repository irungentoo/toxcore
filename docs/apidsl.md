This folder contains the input file (``tox.in.h``) that has to be used to generate the ``tox.h`` api with: https://github.com/TokTok/apidsl

# Minimal requirements

There are some minimal requirements to contribute to ``tox.h``:
* unix environment
* ``astyle`` ``>=2.03``
* [``apidsl``](https://github.com/TokTok/apidsl) (you can use provided service with curl instead)

## Quick way

If you want to do it quickly and you don't have time for anything other than copypasting commands, you should have ``curl`` installed.


1. Make sure that you have ``curl`` and ``>=astyle-2.03`` installed
2. Modify [``tox.api.h``](/toxcore/tox.api.h)
3. Run command below ↓

Command to run from ``toxcore`` directory (quick way, involves using curl):
```bash
# For tox.h:
curl -X POST --data-binary @- https://apidsl.herokuapp.com/apidsl \
  < toxcore/tox.api.h \
  | astyle --options=other/astyle/astylerc \
  > toxcore/tox.h
# For toxav.h:
curl -X POST --data-binary @- https://apidsl.herokuapp.com/apidsl \
  < toxav/toxav.api.h \
  | astyle --options=other/astyle/astylerc \
  > toxav/toxav.h
```

You may want to make sure with ``git diff`` that changes made in ``tox.h`` reflect changes in ``tox.in.h``.

And you're done.


## Manually

If you prefer to have more control over what is happening, there are steps below:

1. Install [``apidsl``](https://github.com/TokTok/apidsl)
2. Install ``astyle``, version 2.03 or later.
3. Modify [``tox.api.h``](/toxcore/tox.api.h)
4. Use ``apidsl`` ``??``
5. Parse generated ``tox.h`` with astyle, minimal command for it would be:
```bash
astyle --options=other/astyle/astylerc toxcore/tox.h
```

**Always pass output from ``apidsl`` through astyle.**
