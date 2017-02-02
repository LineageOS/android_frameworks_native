#include "private/dvr/revision.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <log/log.h>

#include "revision_path.h"

namespace {

// Allows quicker access to the product revision. If non-zero, then
// the product revision file has already been processed.
static bool global_product_revision_processed = false;

static bool global_serial_number_processed = false;

// The product.
static DvrProduct global_product = DVR_PRODUCT_UNKNOWN;

// The revision.
static DvrRevision global_revision = DVR_REVISION_UNKNOWN;

// Maximum size of the product revision string.
constexpr int kProductRevisionStringSize = 32;

// Maximum size of the serial number.
constexpr int kSerialNumberStringSize = 32;

// The product revision string.
static char global_product_revision_str[kProductRevisionStringSize + 1] = "";

// The serial number string
static char global_serial_number[kSerialNumberStringSize + 1] = "";

// Product and revision combinations.
struct DvrProductRevision {
  const char* str;
  DvrProduct product;
  DvrRevision revision;
};

// Null-terminated list of all product and revision combinations.
static constexpr DvrProductRevision kProductRevisions[] = {
    {"a00-p1", DVR_PRODUCT_A00, DVR_REVISION_P1},
    {"a00-p2", DVR_PRODUCT_A00, DVR_REVISION_P2},
    {"a00-p3", DVR_PRODUCT_A00, DVR_REVISION_P3},
    {"twilight-p1", DVR_PRODUCT_A65R, DVR_REVISION_P1},
    {"twilight-p2", DVR_PRODUCT_A65R, DVR_REVISION_P2},
    {NULL, DVR_PRODUCT_UNKNOWN, DVR_REVISION_UNKNOWN}};

// Read the product revision string, and store the global data.
static void process_product_revision() {
  int fd;
  ssize_t read_rc;
  const DvrProductRevision* product_revision = kProductRevisions;

  // Of course in a multi-threaded environment, for a few microseconds
  // during process startup, it is possible that this function will be
  // called and execute fully multiple times. That is why the product
  // revision string is statically allocated.

  if (global_product_revision_processed)
    return;

  // Whether there was a failure or not, we don't want to do this again.
  // Upon failure it's most likely to fail again anyway.

  fd = open(dvr_product_revision_file_path(), O_RDONLY);
  if (fd < 0) {
    ALOGE("Could not open '%s' to get product revision: %s",
          dvr_product_revision_file_path(), strerror(errno));
    global_product_revision_processed = true;
    return;
  }

  read_rc = read(fd, global_product_revision_str, kProductRevisionStringSize);
  if (read_rc <= 0) {
    ALOGE("Could not read from '%s': %s", dvr_product_revision_file_path(),
          strerror(errno));
    global_product_revision_processed = true;
    return;
  }

  close(fd);

  global_product_revision_str[read_rc] = '\0';

  while (product_revision->str) {
    if (!strcmp(product_revision->str, global_product_revision_str))
      break;
    product_revision++;
  }

  if (product_revision->str) {
    global_product = product_revision->product;
    global_revision = product_revision->revision;
  } else {
    ALOGE("Unable to match '%s' to a product/revision.",
          global_product_revision_str);
  }

  global_product_revision_processed = true;
}

}  // anonymous namespace

extern "C" DvrProduct dvr_get_product() {
  process_product_revision();
  return global_product;
}

extern "C" DvrRevision dvr_get_revision() {
  process_product_revision();
  return global_revision;
}

extern "C" const char* dvr_get_product_revision_str() {
  process_product_revision();
  return global_product_revision_str;
}

extern "C" const char* dvr_get_serial_number() {
  process_product_revision();
  if (global_product == DVR_PRODUCT_A00) {
    if (!global_serial_number_processed) {
#ifdef DVR_HOST
      global_serial_number_processed = true;
#else
      int width = 4;
      uintptr_t addr = 0x00074138;
      uintptr_t endaddr = addr + width - 1;

      int fd = open("/dev/mem", O_RDWR | O_SYNC);
      if (fd < 0) {
        if (errno == EPERM)
          global_serial_number_processed = true;
        fprintf(stderr, "cannot open /dev/mem\n");
        return global_serial_number;
      }

      off64_t mmap_start = addr & ~(PAGE_SIZE - 1);
      size_t mmap_size = endaddr - mmap_start + 1;
      mmap_size = (mmap_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

      void* page = mmap64(0, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                          mmap_start);

      if (page == MAP_FAILED) {
        global_serial_number_processed = true;
        fprintf(stderr, "cannot mmap region\n");
        close(fd);
        return global_serial_number;
      }

      uint32_t* x =
          reinterpret_cast<uint32_t*>((((uintptr_t)page) + (addr & 4095)));
      snprintf(global_serial_number, kSerialNumberStringSize, "%08x", *x);
      global_serial_number_processed = true;

      munmap(page, mmap_size);
      close(fd);
#endif
    }
    return global_serial_number;
  } else {
    return nullptr;
  }
}
