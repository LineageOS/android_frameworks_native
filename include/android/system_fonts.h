/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file system_fonts.h
 * @brief Provides the system font configurations.
 *
 * These APIs provides the list of system installed font files with additional metadata about the
 * font.
 *
 * The ASystemFontIterator_open method will give you an iterator which can iterate all system
 * installed font files as shown in the following example.
 *
 * <code>
 *   ASystemFontIterator* iterator = ASystemFontIterator_open();
 *   ASystemFont* font = NULL;
 *
 *   while ((font = ASystemFontIterator_next(iterator)) != nullptr) {
 *       // Look if the font is your desired one.
 *       if (ASystemFont_getWeight(font) == 400 && !ASystemFont_isItalic(font)
 *           && ASystemFont_getLocale(font) == NULL) {
 *           break;
 *       }
 *       ASystemFont_close(font);
 *   }
 *   ASystemFontIterator_close(iterator);
 *
 *   int fd = open(ASystemFont_getFontFilePath(font), O_RDONLY);
 *   int collectionIndex = ASystemFont_getCollectionINdex(font);
 *   std::vector<std::pair<uint32_t, float>> variationSettings;
 *   for (size_t i = 0; i < ASystemFont_getAxisCount(font); ++i) {
 *       variationSettings.push_back(std::make_pair(
 *           ASystemFont_getAxisTag(font, i),
 *           ASystemFont_getAxisValue(font, i)));
 *   }
 *   ASystemFont_close(font);
 *
 *   // Use this font for your text rendering engine.
 *
 * </code>
 *
 * Available since API level 29.
 */

#ifndef ANDROID_SYSTEM_FONTS_H
#define ANDROID_SYSTEM_FONTS_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/cdefs.h>

/******************************************************************
 *
 * IMPORTANT NOTICE:
 *
 *   This file is part of Android's set of stable system headers
 *   exposed by the Android NDK (Native Development Kit).
 *
 *   Third-party source AND binary code relies on the definitions
 *   here to be FROZEN ON ALL UPCOMING PLATFORM RELEASES.
 *
 *   - DO NOT MODIFY ENUMS (EXCEPT IF YOU ADD NEW 32-BIT VALUES)
 *   - DO NOT MODIFY CONSTANTS OR FUNCTIONAL MACROS
 *   - DO NOT CHANGE THE SIGNATURE OF FUNCTIONS IN ANY WAY
 *   - DO NOT CHANGE THE LAYOUT OR SIZE OF STRUCTURES
 */

__BEGIN_DECLS

#if __ANDROID_API__ >= 29

enum {
    /** The minimum value fot the font weight value. */
    ASYSTEM_FONT_WEIGHT_MIN = 0,

    /** A font weight value for the thin weight. */
    ASYSTEM_FONT_WEIGHT_THIN = 100,

    /** A font weight value for the extra-light weight. */
    ASYSTEM_FONT_WEIGHT_EXTRA_LIGHT = 200,

    /** A font weight value for the light weight. */
    ASYSTEM_FONT_WEIGHT_LIGHT = 300,

    /** A font weight value for the normal weight. */
    ASYSTEM_FONT_WEIGHT_NORMAL = 400,

    /** A font weight value for the medium weight. */
    ASYSTEM_FONT_WEIGHT_MEDIUM = 500,

    /** A font weight value for the semi-bold weight. */
    ASYSTEM_FONT_WEIGHT_SEMI_BOLD = 600,

    /** A font weight value for the bold weight. */
    ASYSTEM_FONT_WEIGHT_BOLD = 700,

    /** A font weight value for the extra-bold weight. */
    ASYSTEM_FONT_WEIGHT_EXTRA_BOLD = 800,

    /** A font weight value for the black weight. */
    ASYSTEM_FONT_WEIGHT_BLACK = 900,

    /** The maximum value for the font weight value. */
    ASYSTEM_FONT_WEIGHT_MAX = 1000
};

/**
 * ASystemFontIterator provides access to the system font configuration.
 *
 * ASystemFontIterator is an iterator for all available system font settings.
 * This iterator is not a thread-safe object. Do not pass this iterator to other threads.
 */
struct ASystemFontIterator;

/**
 * ASystemFont provides information of the single system font configuration.
 */
struct ASystemFont;

/**
 * Create a system font iterator.
 *
 * Use ASystemFont_close() to close the iterator.
 *
 * \return a pointer for a newly allocated iterator, nullptr on failure.
 */
ASystemFontIterator* _Nullable ASystemFontIterator_open() __INTRODUCED_IN(29);

/**
 * Close an opened system font iterator, freeing any related resources.
 *
 * \param a pointer of an iterator for the system fonts. Do nothing if NULL is passed.
 */
void ASystemFontIterator_close(ASystemFontIterator* _Nullable iterator) __INTRODUCED_IN(29);

/**
 * Move to the next system font.
 *
 * \param iterator an iterator for the system fonts. Passing NULL is not allowed.
 * \return a font. If no more font is available, returns nullptr. You need to release the returned
 *         font by ASystemFont_close when it is no longer needed.
 */
ASystemFont* _Nullable ASystemFontIterator_next(ASystemFontIterator* _Nonnull iterator) __INTRODUCED_IN(29);

/**
 * Close an ASystemFont returned by ASystemFontIterator_next.
 *
 * \param font a font returned by ASystemFontIterator_next or ASystemFont_matchFamilyStyleCharacter.
 *        Do nothing if NULL is passed.
 */
void ASystemFont_close(ASystemFont* _Nullable font) __INTRODUCED_IN(29);


/**
 * Select the best font from given parameters.
 *
 * Only generic font families are supported.
 * For more information about generic font families, read [W3C spec](https://www.w3.org/TR/css-fonts-4/#generic-font-families)
 *
 * Even if no font can render the given text, this function will return a non-null result for
 * drawing Tofu character.
 *
 * Examples:
 * <code>
 *  // Simple font query for the ASCII character.
 *  std::vector<uint16_t> text = { 'A' };
 *  ASystemFont font = ASystemFont_matchFamilyStyleCharacter(
 *      "sans", 400, false, "en-US", text.data(), text.length(), &runLength);
 *  // runLength will be 1 and the font will points a valid font file.
 *
 *  // Querying font for CJK characters
 *  std::vector<uint16_t> text = { 0x9AA8 };
 *  ASystemFont font = ASystemFont_matchFamilyStyleCharacter(
 *      "sans", 400, false, "zh-CN,ja-JP", text.data(), text.length(), &runLength);
 *  // runLength will be 1 and the font will points a Simplified Chinese font.
 *  ASystemFont font = ASystemFont_matchFamilyStyleCharacter(
 *      "sans", 400, false, "ja-JP,zh-CN", text.data(), text.length(), &runLength);
 *  // runLength will be 1 and the font will points a Japanese font.
 *
 *  // Querying font for text/color emoji
 *  std::vector<uint16_t> text = { 0xD83D, 0xDC68, 0x200D, 0x2764, 0xFE0F, 0x200D, 0xD83D, 0xDC68 };
 *  ASystemFont font = ASystemFont_matchFamilyStyleCharacter(
 *      "sans", 400, false, "en-US", text.data(), text.length(), &runLength);
 *  // runLength will be 8 and the font will points a color emoji font.
 *
 *  // Mixture of multiple script of characters.
 *  // 0x05D0 is a Hebrew character and 0x0E01 is a Thai character.
 *  std::vector<uint16_t> text = { 0x05D0, 0x0E01 };
 *  ASystemFont font = ASystemFont_matchFamilyStyleCharacter(
 *      "sans", 400, false, "en-US", text.data(), text.length(), &runLength);
 *  // runLength will be 1 and the font will points a Hebrew font.
 * </code>
 *
 * \param familyName a null character terminated font family name
 * \param weight a font weight value. Only from 0 to 1000 value is valid
 * \param italic true if italic, otherwise false.
 * \param languageTags a null character terminated comma separated IETF BCP47 compliant language
 *                     tags.
 * \param text a UTF-16 encoded text buffer to be rendered.
 * \param textLength a length of the given text buffer.
 * \param runLengthOut if not null, the font run length will be filled.
 * \return a font to be used for given text and params. You need to release the returned font by
 *         ASystemFont_close when it is no longer needed.
 */
ASystemFont* _Nonnull ASystemFont_matchFamilyStyleCharacter(
        const char* _Nonnull familyName,
        uint16_t weight,
        bool italic,
        const char* _Nonnull languageTags,
        const uint16_t* _Nonnull text,
        uint32_t textLength,
        uint32_t* _Nullable runLengthOut) __INTRODUCED_IN(29);

/**
 * Return an absolute path to the current font file.
 *
 * Here is a list of font formats returned by this method:
 * <ul>
 *   <li>OpenType</li>
 *   <li>OpenType Font Collection</li>
 *   <li>TrueType</li>
 *   <li>TrueType Collection</li>
 * </ul>
 * The file extension could be one of *.otf, *.ttf, *.otc or *.ttc.
 *
 * The font file returned is guaranteed to be opend with O_RDONLY.
 * Note that the returned pointer is valid until ASystemFont_close() is called for the given font.
 *
 * \param iterator an iterator for the system fonts. Passing NULL is not allowed.
 * \return a string of the font file path.
 */
const char* _Nonnull ASystemFont_getFontFilePath(const ASystemFont* _Nonnull font) __INTRODUCED_IN(29);

/**
 * Return a weight value associated with the current font.
 *
 * The weight values are positive and less than or equal to 1000.
 * Here are pairs of the common names and their values.
 * <p>
 *  <table>
 *  <thead>
 *  <tr>
 *  <th align="center">Value</th>
 *  <th align="center">Name</th>
 *  <th align="center">NDK Definition</th>
 *  </tr>
 *  </thead>
 *  <tbody>
 *  <tr>
 *  <td align="center">100</td>
 *  <td align="center">Thin</td>
 *  <td align="center">{@link ASYSTEM_FONT_WEIGHT_THIN}</td>
 *  </tr>
 *  <tr>
 *  <td align="center">200</td>
 *  <td align="center">Extra Light (Ultra Light)</td>
 *  <td align="center">{@link ASYSTEM_FONT_WEIGHT_EXTRA_LIGHT}</td>
 *  </tr>
 *  <tr>
 *  <td align="center">300</td>
 *  <td align="center">Light</td>
 *  <td align="center">{@link ASYSTEM_FONT_WEIGHT_LIGHT}</td>
 *  </tr>
 *  <tr>
 *  <td align="center">400</td>
 *  <td align="center">Normal (Regular)</td>
 *  <td align="center">{@link ASYSTEM_FONT_WEIGHT_NORMAL}</td>
 *  </tr>
 *  <tr>
 *  <td align="center">500</td>
 *  <td align="center">Medium</td>
 *  <td align="center">{@link ASYSTEM_FONT_WEIGHT_MEDIUM}</td>
 *  </tr>
 *  <tr>
 *  <td align="center">600</td>
 *  <td align="center">Semi Bold (Demi Bold)</td>
 *  <td align="center">{@link ASYSTEM_FONT_WEIGHT_SEMI_BOLD}</td>
 *  </tr>
 *  <tr>
 *  <td align="center">700</td>
 *  <td align="center">Bold</td>
 *  <td align="center">{@link ASYSTEM_FONT_WEIGHT_BOLD}</td>
 *  </tr>
 *  <tr>
 *  <td align="center">800</td>
 *  <td align="center">Extra Bold (Ultra Bold)</td>
 *  <td align="center">{@link ASYSTEM_FONT_WEIGHT_EXTRA_BOLD}</td>
 *  </tr>
 *  <tr>
 *  <td align="center">900</td>
 *  <td align="center">Black (Heavy)</td>
 *  <td align="center">{@link ASYSTEM_FONT_WEIGHT_BLACK}</td>
 *  </tr>
 *  </tbody>
 * </p>
 * Note that the weight value may fall in between above values, e.g. 250 weight.
 *
 * For more information about font weight, read [OpenType usWeightClass](https://docs.microsoft.com/en-us/typography/opentype/spec/os2#usweightclass)
 *
 * \param iterator an iterator for the system fonts. Passing NULL is not allowed.
 * \return a positive integer less than or equal to {@link ASYSTEM_FONT_MAX_WEIGHT} is returned.
 */
uint16_t ASystemFont_getWeight(const ASystemFont* _Nonnull font) __INTRODUCED_IN(29);

/**
 * Return true if the current font is italic, otherwise returns false.
 *
 * \param iterator an iterator for the system fonts. Passing NULL is not allowed.
 * \return true if italic, otherwise false.
 */
bool ASystemFont_isItalic(const ASystemFont* _Nonnull font) __INTRODUCED_IN(29);

/**
 * Return a IETF BCP47 compliant language tag associated with the current font.
 *
 * For information about IETF BCP47, read [Locale.forLanguageTag(java.lang.String)](https://developer.android.com/reference/java/util/Locale.html#forLanguageTag(java.lang.String)")
 *
 * Note that the returned pointer is valid until ASystemFont_close() is called.
 *
 * \param iterator an iterator for the system fonts. Passing NULL is not allowed.
 * \return a IETF BCP47 compliant langauge tag or nullptr if not available.
 */
const char* _Nullable ASystemFont_getLocale(const ASystemFont* _Nonnull font) __INTRODUCED_IN(29);

/**
 * Return a font collection index value associated with the current font.
 *
 * In case the target font file is a font collection (e.g. .ttc or .otc), this
 * returns a non-negative value as an font offset in the collection. This
 * always returns 0 if the target font file is a regular font.
 *
 * \param iterator an iterator for the system fonts. Passing NULL is not allowed.
 * \return a font collection index.
 */
size_t ASystemFont_getCollectionIndex(const ASystemFont* _Nonnull font) __INTRODUCED_IN(29);

/**
 * Return a count of font variation settings associated with the current font
 *
 * The font variation settings are provided as multiple tag-values pairs.
 *
 * For example, bold italic font may have following font variation settings:
 *     'wght' 700, 'slnt' -12
 * In this case, ASystemFont_getAxisCount returns 2 and ASystemFont_getAxisTag
 * and ASystemFont_getAxisValue will return following values.
 * <code>
 *     ASystemFont* font = ASystemFontIterator_next(ite);
 *
 *     // Returns the number of axes
 *     ASystemFont_getAxisCount(font);  // Returns 2
 *
 *     // Returns the tag-value pair for the first axis.
 *     ASystemFont_getAxisTag(font, 0);  // Returns 'wght'(0x77676874)
 *     ASystemFont_getAxisValue(font, 0);  // Returns 700.0
 *
 *     // Returns the tag-value pair for the second axis.
 *     ASystemFont_getAxisTag(font, 1);  // Returns 'slnt'(0x736c6e74)
 *     ASystemFont_getAxisValue(font, 1);  // Returns -12.0
 * </code>
 *
 * For more information about font variation settings, read [Font Variations Table](https://docs.microsoft.com/en-us/typography/opentype/spec/fvar)
 *
 * \param iterator an iterator for the system fonts. Passing NULL is not allowed.
 * \return a number of font variation settings.
 */
size_t ASystemFont_getAxisCount(const ASystemFont* _Nonnull font) __INTRODUCED_IN(29);


/**
 * Return an OpenType axis tag associated with the current font.
 *
 * See ASystemFont_getAxisCount for more details.
 *
 * \param iterator an iterator for the system fonts. Passing NULL is not allowed.
 * \param an index to the font variation settings. Passing value larger than or
 *        equal to {@link ASystemFont_getAxisCount} is not allowed.
 * \return an OpenType axis tag value for the given font variation setting.
 */
uint32_t ASystemFont_getAxisTag(const ASystemFont* _Nonnull font, uint32_t axisIndex)
      __INTRODUCED_IN(29);

/**
 * Return an OpenType axis value associated with the current font.
 *
 * See ASystemFont_getAxisCount for more details.
 *
 * \param iterator an iterator for the system fonts. Passing NULL is not allowed.
 * \param an index to the font variation settings. Passing value larger than or
 *         equal to {@link ASYstemFont_getAxisCount} is not allwed.
 * \return a float value for the given font variation setting.
 */
float ASystemFont_getAxisValue(const ASystemFont* _Nonnull font, uint32_t axisIndex)
      __INTRODUCED_IN(29);

#endif // __ANDROID_API__ >= 29

__END_DECLS

#endif // ANDROID_SYSTEM_FONTS_H
