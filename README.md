# ![Project Tox](https://raw.github.com/TokTok/c-toxcore/master/other/tox.png "Project Tox")

**Current Coverage:** [![coverage](https://codecov.io/gh/TokTok/c-toxcore/branch/master/graph/badge.svg?token=BRfCKo02De)](https://codecov.io/gh/TokTok/c-toxcore)

[**Website**](https://tox.chat) **|** [**Wiki**](https://wiki.tox.chat/) **|** [**Blog**](https://blog.tox.chat/) **|** [**FAQ**](https://wiki.tox.chat/doku.php?id=users:faq) **|** [**Binaries/Downloads**](https://tox.chat/download.html) **|** [**Clients**](https://wiki.tox.chat/doku.php?id=clients) **|** [**Compiling**](/INSTALL.md)

**IRC Channels:** Users: [#tox@libera.chat](https://web.libera.chat/#tox), Developers: [#toktok@libera.chat](https://web.libera.chat/#toktok)

## What is Tox

Tox is a peer to peer (serverless) instant messenger aimed at making security
and privacy easy to obtain for regular users. It uses
[NaCl](https://nacl.cr.yp.to/) for its encryption and authentication.

## IMPORTANT!

### ![Danger: Experimental](other/tox-warning.png)

This is an **experimental** cryptographic network library. It has not been
formally audited by an independent third party that specializes in
cryptography or cryptanalysis. **Use this library at your own risk.**

The underlying crypto library [NaCl](https://nacl.cr.yp.to/install.html)
provides reliable encryption, but the security model has not yet been fully
specified. See [issue 210](https://github.com/TokTok/c-toxcore/issues/210) for
a discussion on developing a threat model. See other issues for known
weaknesses (e.g. [issue 426](https://github.com/TokTok/c-toxcore/issues/426)
describes what can happen if your secret key is stolen).

## Toxcore Development Roadmap

The roadmap and changelog are generated from GitHub issues. You may view them
on the website, where they are updated at least once every 24 hours:

-   Changelog: https://toktok.ltd/changelog/c-toxcore
-   Roadmap: https://toktok.ltd/roadmap/c-toxcore

## Installing toxcore

Detailed installation instructions can be found in [INSTALL.md](INSTALL.md).

In a nutshell, if you have [libsodium](https://github.com/jedisct1/libsodium)
installed, run:

```sh
mkdir _build && cd _build
cmake ..
make
sudo make install
```

If you have [libvpx](https://github.com/webmproject/libvpx) and
[opus](https://github.com/xiph/opus) installed, the above will also build the
A/V library for multimedia chats.

## Using toxcore

The simplest "hello world" example could be an echo bot. Here we will walk
through the implementation of a simple bot.

### Creating the tox instance

All toxcore API functions work with error parameters. They are enums with one
`OK` value and several error codes that describe the different situations in
which the function might fail.

```c
TOX_ERR_NEW err_new;
Tox *tox = tox_new(NULL, &err_new);
if (err_new != TOX_ERR_NEW_OK) {
  fprintf(stderr, "tox_new failed with error code %d\n", err_new);
  exit(1);
}
```

Here, we simply exit the program, but in a real client you will probably want
to do some error handling and proper error reporting to the user. The `NULL`
argument given to the first parameter of `tox_new` is the `Tox_Options`. It
contains various write-once network settings and allows you to load a
previously serialised instance. See [toxcore/tox.h](tox.h) for details.

### Setting up callbacks

Toxcore works with callbacks that you can register to listen for certain
events. Examples of such events are "friend request received" or "friend sent
a message". Search the API for `tox_callback_*` to find all of them.

Here, we will set up callbacks for receiving friend requests and receiving
messages. We will always accept any friend request (because we're a bot), and
when we receive a message, we send it back to the sender.

```c
tox_callback_friend_request(tox, handle_friend_request);
tox_callback_friend_message(tox, handle_friend_message);
```

These two function calls set up the callbacks. Now we also need to implement
these "handle" functions.

### Handle friend requests

```c
static void handle_friend_request(
  Tox *tox, const uint8_t *public_key, const uint8_t *message, size_t length,
  void *user_data) {
  // Accept the friend request:
  TOX_ERR_FRIEND_ADD err_friend_add;
  tox_friend_add_norequest(tox, public_key, &err_friend_add);
  if (err_friend_add != TOX_ERR_FRIEND_ADD_OK) {
    fprintf(stderr, "unable to add friend: %d\n", err_friend_add);
  }
}
```

The `tox_friend_add_norequest` function adds the friend without sending them a
friend request. Since we already got a friend request, this is the right thing
to do. If you wanted to send a friend request yourself, you would use
`tox_friend_add`, which has an extra parameter for the message.

### Handle messages

Now, when the friend sends us a message, we want to respond to them by sending
them the same message back. This will be our "echo".

```c
static void handle_friend_message(
  Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type,
  const uint8_t *message, size_t length,
  void *user_data) {
  TOX_ERR_FRIEND_SEND_MESSAGE err_send;
  tox_friend_send_message(tox, friend_number, type, message, length,
    &err_send);
  if (err_send != TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
    fprintf(stderr, "unable to send message back to friend %d: %d\n",
      friend_number, err_send);
  }
}
```

That's it for the setup. Now we want to actually run the bot.

### Main event loop

Toxcore works with a main event loop function `tox_iterate` that you need to
call at a certain frequency dictated by `tox_iteration_interval`. This is a
polling function that receives new network messages and processes them.

```c
while (true) {
  usleep(1000 * tox_iteration_interval(tox));
  tox_iterate(tox, NULL);
}
```

That's it! Now you have a working echo bot. The only problem is that since Tox
works with public keys, and you can't really guess your bot's public key, you
can't add it as a friend in your client. For this, we need to call another API
function: `tox_self_get_address(tox, address)`. This will fill the 38 byte
friend address into the `address` buffer. You can then display that binary
string as hex and input it into your client. Writing a `bin2hex` function is
left as exercise for the reader.

We glossed over a lot of details, such as the user data which we passed to
`tox_iterate` (passing `NULL`), bootstrapping into an actual network (this bot
will work in the LAN, but not on an internet server) and the fact that we now
have no clean way of stopping the bot (`while (true)`). If you want to write a
real bot, you will probably want to read up on all the API functions. Consult
the API documentation in [toxcore/tox.h](toxcore/tox.h) for more information.

### Other resources

- [Another echo bot](https://wiki.tox.chat/developers/client_examples/echo_bot)
- [minitox](https://github.com/hqwrong/minitox) (A minimal tox client)
