#ifndef STARBURST_EVASION_SLEEP_MASK_TYPES_H
#define STARBURST_EVASION_SLEEP_MASK_TYPES_H

/*
 * Sleep mask type constants.
 *
 * Separated from sleep_masks.h so that any translation unit can test
 * SLEEP_MASK_TYPE without pulling in the mask function definitions
 * (which must only be compiled inside evasion.cc).
 */

#define MASK_DEFAULT    0
#define MASK_FULL_IMAGE 1
#define MASK_HEAP       2
#define MASK_CUSTOM     3
#define MASK_EKKO       4

#endif /* STARBURST_EVASION_SLEEP_MASK_TYPES_H */
