This folder contains the input file that can be used to generate the tox.h api 
with: https://github.com/iphydf/apidsl

You can also use the following command if you can't install it:

```
curl -X POST --data-binary @- https://criticism.herokuapp.com/apidsl < tox.in.h > tox.h
```

Note that the output must be passed through astyle with the config in 
other/astyle/astylerc to generate the exact same file.
