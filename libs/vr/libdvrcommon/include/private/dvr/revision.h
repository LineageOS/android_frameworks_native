#ifndef LIBS_VR_LIBDVRCOMMON_INCLUDE_PRIVATE_DVR_REVISION_H_
#define LIBS_VR_LIBDVRCOMMON_INCLUDE_PRIVATE_DVR_REVISION_H_

#ifdef __cplusplus
extern "C" {
#endif

// List of DreamOS products
typedef enum DvrProduct {
  DVR_PRODUCT_UNKNOWN,
  DVR_PRODUCT_A00,
  DVR_PRODUCT_A65R,
  DVR_PRODUCT_TWILIGHT = DVR_PRODUCT_A65R
} DvrProduct;

// List of possible revisions.
typedef enum DvrRevision {
  DVR_REVISION_UNKNOWN,
  DVR_REVISION_P1,
  DVR_REVISION_P2,
  DVR_REVISION_P3,
} DvrRevision;

// Query the device's product.
//
// @return DvrProduct value, or DvrProductUnknown on error.
DvrProduct dvr_get_product();

// Query the device's revision.
//
// @return DvrRevision value, or DvrRevisionUnknown on error.
DvrRevision dvr_get_revision();

// Returns the device's board revision string.
//
// @return NULL-terminated string such as 'a00-p1'.
const char* dvr_get_product_revision_str();

// Returns the device's serial number.
//
// @return Returns NULL on error, or a NULL-terminated string.
const char* dvr_get_serial_number();

#ifdef __cplusplus
}
#endif  // extern "C"
#endif  // LIBS_VR_LIBDVRCOMMON_INCLUDE_PRIVATE_DVR_REVISION_H_
