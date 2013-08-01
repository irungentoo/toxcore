# Using Tox
1. [Build Tox](../INSTALL.md)
2. Fix errors
3. Consult IRC for help
4. Go on debugging journey for devs
5. Build Tox for real
6. ???

For all the work we've put into Tox so far,
there isn't yet a decent guide for how you _use_
Tox. Here's a user-friendly attempt at it.

1. Connect to the network!
    + You need to connect to a bootstrapping server, to give you a public key.
    + Where can I find a public server? Right here, as of now:
      (the help message from running `nTox` with no args will help)
        + `198.46.136.167 33445 728925473812C7AAC482BE7250BCCAD0B8CB9F737BF3D42ABD34459C1768F854`
        + `192.81.133.111 33445 8CD5A9BF0A6CE358BA36F7A653F99FA6B258FF756E490F52C1F98CC420F78858`
        + `66.175.223.88 33445  AC4112C975240CAD260BB2FCD134266521FAAF0A5D159C5FD3201196191E4F5D`
        + `192.184.81.118 33445 5CD7EB176C19A2FD840406CD56177BB8E75587BB366F7BB3004B19E3EDC04143`
2. Find a friend!
    + Now that you're on the network, you need a friend. To get one of those,
       you need to to send or receive a request. What's a request, you ask?
       It's like a friend request, but we use really scary and cryptic numbers
       instead of names. When `nTox` starts, it shows _your_ long, scary number,
       called your *public key*. Give that to people, and they can add you as
       a "friend". Or, you can add someone else, with the `/f` command, if you like.
3. Chat it up!
    + Now use the `/m` command to send a message to someone. Wow, you're chatting!
4. But something broke!
    + Yeah, pre-alpha-alpha software tends to do that. We're working on it.
    + Please report all crashes to either the GitHub page, or `#tox-dev` on freenode.
5. Nothing broke, but what does `/f` mean?
    + `nTox` parses text as a command if the first character is a forward-slash (`/`).
      You can check all commands in commands.md.
6. Use and support Tox!
    + Code for us, debug for us, document for us, translate for us, even just talk about us!
    + The more interest we get, the more work gets done, the better Tox is.
