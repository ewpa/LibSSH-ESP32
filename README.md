ESP32 SSH client/server on Arduino
==================================

This is a port of the excellent libssh.org library to an Arduino library for
the ESP32 microcontroller.

It lets you run an SSH server and SSH client on your ESP32 and use it over
WiFi and Ethernet.  Write your code and add the following include and
initialization lines to your sketch:

    #include "libssh_esp32.h"
    libssh_begin();

This library is currently built and tested against version 1.0.4 of the ESP32
Arduino core.  Please refer to the GIT log for the latest changes.  Further
information on this port can be found at the following address.

  https://www.ewan.cc/?q=node/157

This port created by Ewan Parker on 18th April 2020.

```
  _   _   _                          _
 (_) (_) (_)                        (_)
 (_)  _  (_) _         _  _   _  _  (_) _
 (_) (_) (_)(_) _     (_)(_) (_)(_) (_)(_) _
 (_) (_) (_)   (_)  _ (_)  _ (_)    (_)   (_)
 (_) (_) (_)(_)(_) (_)(_) (_)(_)    (_)   (_).org

 The SSH library

```

# Why?

Why not ? :) I've began to work on my own implementation of the ssh protocol
because i didn't like the currently public ones.
Not any allowed you to import and use the functions as a powerful library,
and so i worked on a library-based SSH implementation which was non-existing
in the free and open source software world.


# How/Who?

If you downloaded this file, you must know what it is : a library for
accessing ssh client services through C libraries calls in a simple manner.
Everybody can use this software under the terms of the LGPL - see the COPYING
file

If you ask yourself how to compile libssh, please read INSTALL before anything.

# Where ?

https://www.libssh.org

# Contributing

Please read the file 'SubmittingPatches' next to this README file. It explains
our copyright policy and how you should send patches for upstream inclusion.

Have fun and happy libssh hacking!

The libssh Team
