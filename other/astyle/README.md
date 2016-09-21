This directory can house various tools and utilities.

# How to use astyle

## Manually

### For all files

Run from ``toxcore`` directory:
```bash
astyle --options=./other/astyle/astylerc ./toxcore/*.c ./toxcore/*.h ./toxdns/*.c ./toxdns/*.h ./testing/*.c ./toxav/*.c ./toxav/*.h ./other/*.c ./other/bootstrap_daemon/*.c ./toxencryptsave/*.c ./toxencryptsave/*.h ./auto_tests/*.c
```

### For selected file

Run from ``toxcore`` directory, e.g. for [``tox.h``](/toxcore/tox.h) file:
```bash
astyle --options=./other/astyle/astylerc ./toxcore/tox.h
```


## Automatically, as pre-commit hook (*NIX only)

Copy [``astylerc``](/other/astyle/astylerc) to ``toxcore/.git/hooks``



# Why

``astylerc`` - this file can be used in the pre-commit hook to try its best at making the code conform to the coding style of toxcore.

Furthermore, it is being used to format ``tox.h`` after using ``apidsl`` to generate it.
