#include "revision_path.h"

namespace {

// The path to the product revision file.
static const char* kProductRevisionFilePath =
    "/sys/firmware/devicetree/base/goog,board-revision";

}  // anonymous namespace

// This exists in a separate file so that it can be replaced for
// testing.
const char* dvr_product_revision_file_path() {
  return kProductRevisionFilePath;
}
