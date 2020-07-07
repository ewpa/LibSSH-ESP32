// ESP32 libssh port.
// libssh_esp32_compat.h
//
// Ewan Parker, created 4th July 2020.
// Missing implementations needed to link libssh with ESP32.
//
// Copyright (C) 2020 Ewan Parker.

#ifndef LIBSSH_ESP32_COMPAT_H
#define LIBSSH_ESP32_COMPAT_H

__attribute__((weak))
int gethostname(char *name, int len);

#endif /* LIBSSH_ESP32_COMPAT_H */
