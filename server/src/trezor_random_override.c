#include <stdint.h>
#include <stdlib.h>

#if defined(__APPLE__)
#include <stdlib.h>
#elif defined(__linux__)
#include <errno.h>
#include <fcntl.h>
#include <sys/random.h>
#include <unistd.h>
#endif

// Override trezor-crypto weak RNG with OS RNG.
// NOTE: For production, you should also implement random_reseed() appropriately.

void random_buffer(uint8_t *buf, size_t len);

uint32_t random32(void) {
  uint32_t v = 0;
  random_buffer((uint8_t *)&v, sizeof(v));
  return v;
}

void random_buffer(uint8_t *buf, size_t len) {
#if defined(__APPLE__)
  arc4random_buf(buf, len);
#elif defined(__linux__)
  size_t off = 0;
  while (off < len) {
    ssize_t n = getrandom(buf + off, len - off, 0);
    if (n < 0) {
      if (errno == EINTR) continue;
      break;
    }
    off += (size_t)n;
  }
  if (off == len) return;

  int fd = open("/dev/urandom", O_RDONLY);
  if (fd >= 0) {
    while (off < len) {
      ssize_t n = read(fd, buf + off, len - off);
      if (n < 0) {
        if (errno == EINTR) continue;
        break;
      }
      off += (size_t)n;
    }
    close(fd);
  }
  // If we still failed, fill remainder with zeros (best-effort).
  while (off < len) {
    buf[off++] = 0;
  }
#else
  // Fallback: best-effort, not secure.
  for (size_t i = 0; i < len; i++) buf[i] = 0;
#endif
}

