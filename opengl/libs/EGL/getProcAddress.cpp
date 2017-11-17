/*
 ** Copyright 2009, The Android Open Source Project
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

#include <ctype.h>
#include <stdlib.h>
#include <errno.h>

#include <cutils/log.h>

#include "egldefs.h"

// ----------------------------------------------------------------------------
namespace android {
// ----------------------------------------------------------------------------

#undef API_ENTRY
#undef CALL_GL_EXTENSION_API
#undef GL_EXTENSION
#undef GL_EXTENSION_NAME
#undef GL_EXTENSION_ARRAY
#undef GL_EXTENSION_LIST
#undef GET_TLS

#if defined(__arm__)

    #define GET_TLS(reg) "mrc p15, 0, " #reg ", c13, c0, 3 \n"

    #define API_ENTRY(_api) __attribute__((naked)) _api

#ifdef NV_ANDROID_FRAMEWORK_ENHANCEMENTS
    #define CALL_GL_EXTENSION_API(_api)                         \
         asm volatile(                                          \
            GET_TLS(r12)                                        \
            "ldr   r12, [r12, %[tls]] \n"                       \
            "cmp   r12, #0            \n"                       \
            "addne r12, %[api]        \n"                       \
            "addne r12, %[spl]        \n"                       \
            "ldrne r12, [r12, %[ext]] \n"                       \
            "cmpne r12, #0            \n"                       \
            "bxne  r12                \n"                       \
            "bx    lr                 \n"                       \
            :                                                   \
            : [tls] "J"(TLS_SLOT_OPENGL_API*4),                 \
              [ext] "J"(__builtin_offsetof(gl_hooks_t,          \
                                      ext.extensions[0])),      \
              [api] "J"(((_api*sizeof(void*))/1024)*1024),      \
              [spl] "J"((_api*sizeof(void*))%1024)              \
            : "r12"                                             \
            );
#else
    #define CALL_GL_EXTENSION_API(_api)                         \
         asm volatile(                                          \
            GET_TLS(r12)                                        \
            "ldr   r12, [r12, %[tls]] \n"                       \
            "cmp   r12, #0            \n"                       \
            "addne r12, %[api]        \n"                       \
            "ldrne r12, [r12, %[ext]] \n"                       \
            "cmpne r12, #0            \n"                       \
            "bxne  r12                \n"                       \
            "bx    lr                 \n"                       \
            :                                                   \
            : [tls] "J"(TLS_SLOT_OPENGL_API*4),                 \
              [ext] "J"(__builtin_offsetof(gl_hooks_t,          \
                                      ext.extensions[0])),      \
              [api] "J"(_api*sizeof(void*))                     \
            : "r12"                                             \
            );
#endif

#elif defined(__aarch64__)

    #define API_ENTRY(_api) __attribute__((noinline)) _api

    #define CALL_GL_EXTENSION_API(_api)                             \
        asm volatile(                                               \
            "mrs x16, tpidr_el0\n"                                  \
            "ldr x16, [x16, %[tls]]\n"                              \
            "cbz x16, 1f\n"                                         \
            "ldr x16, [x16, %[api]]\n"                              \
            "cbz x16, 1f\n"                                         \
            "br  x16\n"                                             \
            "1:\n"                                                  \
            :                                                       \
            : [tls] "i" (TLS_SLOT_OPENGL_API * sizeof(void*)),      \
              [api] "i" (__builtin_offsetof(gl_hooks_t,             \
                                        ext.extensions[_api]))      \
            : "x16"                                                 \
        );

#elif defined(__i386__)

    #define API_ENTRY(_api) __attribute__((noinline,optimize("omit-frame-pointer"))) _api

    #define CALL_GL_EXTENSION_API(_api)                         \
         register void** fn;                                    \
         __asm__ volatile(                                      \
            "mov %%gs:0, %[fn]\n"                               \
            "mov %P[tls](%[fn]), %[fn]\n"                       \
            "test %[fn], %[fn]\n"                               \
            "cmovne %P[api](%[fn]), %[fn]\n"                    \
            "test %[fn], %[fn]\n"                               \
            "je 1f\n"                                           \
            "jmp *%[fn]\n"                                      \
            "1:\n"                                              \
            : [fn] "=r" (fn)                                    \
            : [tls] "i" (TLS_SLOT_OPENGL_API*sizeof(void*)),    \
              [api] "i" (__builtin_offsetof(gl_hooks_t,         \
                                      ext.extensions[_api]))    \
            : "cc"                                              \
            );

#elif defined(__x86_64__)

    #define API_ENTRY(_api) __attribute__((noinline,optimize("omit-frame-pointer"))) _api

    #define CALL_GL_EXTENSION_API(_api)                         \
         register void** fn;                                    \
         __asm__ volatile(                                      \
            "mov %%fs:0, %[fn]\n"                               \
            "mov %P[tls](%[fn]), %[fn]\n"                       \
            "test %[fn], %[fn]\n"                               \
            "cmovne %P[api](%[fn]), %[fn]\n"                    \
            "test %[fn], %[fn]\n"                               \
            "je 1f\n"                                           \
            "jmp *%[fn]\n"                                      \
            "1:\n"                                              \
            : [fn] "=r" (fn)                                    \
            : [tls] "i" (TLS_SLOT_OPENGL_API*sizeof(void*)),    \
              [api] "i" (__builtin_offsetof(gl_hooks_t,         \
                                      ext.extensions[_api]))    \
            : "cc"                                              \
            );

#elif defined(__mips64)

        #define API_ENTRY(_api) __attribute__((noinline)) _api

        #define CALL_GL_EXTENSION_API(_api, ...)                    \
            register unsigned int _t0 asm("$12");                   \
            register unsigned int _fn asm("$25");                   \
            register unsigned int _tls asm("$3");                   \
            asm volatile(                                           \
                ".set  push\n\t"                                    \
                ".set  noreorder\n\t"                               \
                "rdhwr %[tls], $29\n\t"                             \
                "ld    %[t0], %[OPENGL_API](%[tls])\n\t"            \
                "beqz  %[t0], 1f\n\t"                               \
                " move %[fn], $ra\n\t"                              \
                "ld    %[t0], %[API](%[t0])\n\t"                    \
                "beqz  %[t0], 1f\n\t"                               \
                " nop\n\t"                                          \
                "move  %[fn], %[t0]\n\t"                            \
                "1:\n\t"                                            \
                "jalr  $0, %[fn]\n\t"                               \
                " nop\n\t"                                          \
                ".set  pop\n\t"                                     \
                : [fn] "=c"(_fn),                                   \
                  [tls] "=&r"(_tls),                                \
                  [t0] "=&r"(_t0)                                   \
                : [OPENGL_API] "I"(TLS_SLOT_OPENGL_API*4),          \
                  [API] "I"(__builtin_offsetof(gl_hooks_t,          \
                                          ext.extensions[_api]))    \
                :                                                   \
            );

#elif defined(__mips__)

        #define API_ENTRY(_api) __attribute__((noinline)) _api

        #define CALL_GL_EXTENSION_API(_api, ...)                    \
            register unsigned int _t0 asm("$8");                    \
            register unsigned int _fn asm("$25");                    \
            register unsigned int _tls asm("$3");                   \
            asm volatile(                                           \
                ".set  push\n\t"                                    \
                ".set  noreorder\n\t"                               \
                ".set  mips32r2\n\t"                                \
                "rdhwr %[tls], $29\n\t"                             \
                "lw    %[t0], %[OPENGL_API](%[tls])\n\t"            \
                "beqz  %[t0], 1f\n\t"                               \
                " move %[fn], $ra\n\t"                              \
                "lw    %[t0], %[API](%[t0])\n\t"                    \
                "beqz  %[t0], 1f\n\t"                               \
                " nop\n\t"                                          \
                "move  %[fn], %[t0]\n\t"                            \
                "1:\n\t"                                            \
                "jalr  $0, %[fn]\n\t"                               \
                " nop\n\t"                                          \
                ".set  pop\n\t"                                     \
                : [fn] "=c"(_fn),                                   \
                  [tls] "=&r"(_tls),                                \
                  [t0] "=&r"(_t0)                                   \
                : [OPENGL_API] "I"(TLS_SLOT_OPENGL_API*4),          \
                  [API] "I"(__builtin_offsetof(gl_hooks_t,          \
                                          ext.extensions[_api]))    \
                :                                                   \
            );

#endif

#if defined(CALL_GL_EXTENSION_API)
    #define GL_EXTENSION_NAME(_n)   __glExtFwd##_n

    #define GL_EXTENSION(_n)                         \
        void API_ENTRY(GL_EXTENSION_NAME(_n))() {    \
            CALL_GL_EXTENSION_API(_n);               \
        }
#else
        #define GL_EXTENSION_NAME(_n) NULL

        #define GL_EXTENSION(_n)

        #warning "eglGetProcAddress() partially supported"
#endif


#ifdef NV_ANDROID_FRAMEWORK_ENHANCEMENTS
#define GL_EXTENSION_LIST(name) \
    name(0)   name(1)   name(2)   name(3)   name(4)   name(5)   name(6)   name(7)  \
    name(8)   name(9)   name(10)  name(11)  name(12)  name(13)  name(14)  name(15) \
    name(16)  name(17)  name(18)  name(19)  name(20)  name(21)  name(22)  name(23) \
    name(24)  name(25)  name(26)  name(27)  name(28)  name(29)  name(30)  name(31) \
    name(32)  name(33)  name(34)  name(35)  name(36)  name(37)  name(38)  name(39) \
    name(40)  name(41)  name(42)  name(43)  name(44)  name(45)  name(46)  name(47) \
    name(48)  name(49)  name(50)  name(51)  name(52)  name(53)  name(54)  name(55) \
    name(56)  name(57)  name(58)  name(59)  name(60)  name(61)  name(62)  name(63) \
    name(64)  name(65)  name(66)  name(67)  name(68)  name(69)  name(70)  name(71) \
    name(72)  name(73)  name(74)  name(75)  name(76)  name(77)  name(78)  name(79) \
    name(80)  name(81)  name(82)  name(83)  name(84)  name(85)  name(86)  name(87) \
    name(88)  name(89)  name(90)  name(91)  name(92)  name(93)  name(94)  name(95) \
    name(96)  name(97)  name(98)  name(99)  \
    name(100) name(101) name(102) name(103) name(104) name(105) name(106) name(107) \
    name(108) name(109) name(110) name(111) name(112) name(113) name(114) name(115) \
    name(116) name(117) name(118) name(119) name(120) name(121) name(122) name(123) \
    name(124) name(125) name(126) name(127) name(128) name(129) name(130) name(131) \
    name(132) name(133) name(134) name(135) name(136) name(137) name(138) name(139) \
    name(140) name(141) name(142) name(143) name(144) name(145) name(146) name(147) \
    name(148) name(149) name(150) name(151) name(152) name(153) name(154) name(155) \
    name(156) name(157) name(158) name(159) name(160) name(161) name(162) name(163) \
    name(164) name(165) name(166) name(167) name(168) name(169) name(170) name(171) \
    name(172) name(173) name(174) name(175) name(176) name(177) name(178) name(179) \
    name(180) name(181) name(182) name(183) name(184) name(185) name(186) name(187) \
    name(188) name(189) name(190) name(191) name(192) name(193) name(194) name(195) \
    name(196) name(197) name(198) name(199) \
    name(200) name(201) name(202) name(203) name(204) name(205) name(206) name(207) \
    name(208) name(209) name(210) name(211) name(212) name(213) name(214) name(215) \
    name(216) name(217) name(218) name(219) name(220) name(221) name(222) name(223) \
    name(224) name(225) name(226) name(227) name(228) name(229) name(230) name(231) \
    name(232) name(233) name(234) name(235) name(236) name(237) name(238) name(239) \
    name(240) name(241) name(242) name(243) name(244) name(245) name(246) name(247) \
    name(248) name(249) name(250) name(251) name(252) name(253) name(254) name(255) \
    name(256) name(257) name(258) name(259) name(260) name(261) name(262) name(263) \
    name(264) name(265) name(266) name(267) name(268) name(269) name(270) name(271) \
    name(272) name(273) name(274) name(275) name(276) name(277) name(278) name(279) \
    name(280) name(281) name(282) name(283) name(284) name(285) name(286) name(287) \
    name(288) name(289) name(290) name(291) name(292) name(293) name(294) name(295) \
    name(296) name(297) name(298) name(299) \
    name(300) name(301) name(302) name(303) name(304) name(305) name(306) name(307) \
    name(308) name(309) name(310) name(311) name(312) name(313) name(314) name(315) \
    name(316) name(317) name(318) name(319) name(320) name(321) name(322) name(323) \
    name(324) name(325) name(326) name(327) name(328) name(329) name(330) name(331) \
    name(332) name(333) name(334) name(335) name(336) name(337) name(338) name(339) \
    name(340) name(341) name(342) name(343) name(344) name(345) name(346) name(347) \
    name(348) name(349) name(350) name(351) name(352) name(353) name(354) name(355) \
    name(356) name(357) name(358) name(359) name(360) name(361) name(362) name(363) \
    name(364) name(365) name(366) name(367) name(368) name(369) name(370) name(371) \
    name(372) name(373) name(374) name(375) name(376) name(377) name(378) name(379) \
    name(380) name(381) name(382) name(383) name(384) name(385) name(386) name(387) \
    name(388) name(389) name(390) name(391) name(392) name(393) name(394) name(395) \
    name(396) name(397) name(398) name(399) \
    name(400) name(401) name(402) name(403) name(404) name(405) name(406) name(407) \
    name(408) name(409) name(410) name(411) name(412) name(413) name(414) name(415) \
    name(416) name(417) name(418) name(419) name(420) name(421) name(422) name(423) \
    name(424) name(425) name(426) name(427) name(428) name(429) name(430) name(431) \
    name(432) name(433) name(434) name(435) name(436) name(437) name(438) name(439) \
    name(440) name(441) name(442) name(443) name(444) name(445) name(446) name(447) \
    name(448) name(449) name(450) name(451) name(452) name(453) name(454) name(455) \
    name(456) name(457) name(458) name(459) name(460) name(461) name(462) name(463) \
    name(464) name(465) name(466) name(467) name(468) name(469) name(470) name(471) \
    name(472) name(473) name(474) name(475) name(476) name(477) name(478) name(479) \
    name(480) name(481) name(482) name(483) name(484) name(485) name(486) name(487) \
    name(488) name(489) name(490) name(491) name(492) name(493) name(494) name(495) \
    name(496) name(497) name(498) name(499) \
    name(500) name(501) name(502) name(503) name(504) name(505) name(506) name(507) \
    name(508) name(509) name(510) name(511) name(512) name(513) name(514) name(515) \
    name(516) name(517) name(518) name(519) name(520) name(521) name(522) name(523) \
    name(524) name(525) name(526) name(527) name(528) name(529) name(530) name(531) \
    name(532) name(533) name(534) name(535) name(536) name(537) name(538) name(539) \
    name(540) name(541) name(542) name(543) name(544) name(545) name(546) name(547) \
    name(548) name(549) name(550) name(551) name(552) name(553) name(554) name(555) \
    name(556) name(557) name(558) name(559) name(560) name(561) name(562) name(563) \
    name(564) name(565) name(566) name(567) name(568) name(569) name(570) name(571) \
    name(572) name(573) name(574) name(575) name(576) name(577) name(578) name(579) \
    name(580) name(581) name(582) name(583) name(584) name(585) name(586) name(587) \
    name(588) name(589) name(590) name(591) name(592) name(593) name(594) name(595) \
    name(596) name(597) name(598) name(599) \
    name(600) name(601) name(602) name(603) name(604) name(605) name(606) name(607) \
    name(608) name(609) name(610) name(611) name(612) name(613) name(614) name(615) \
    name(616) name(617) name(618) name(619) name(620) name(621) name(622) name(623) \
    name(624) name(625) name(626) name(627) name(628) name(629) name(630) name(631) \
    name(632) name(633) name(634) name(635) name(636) name(637) name(638) name(639) \
    name(640) name(641) name(642) name(643) name(644) name(645) name(646) name(647) \
    name(648) name(649) name(650) name(651) name(652) name(653) name(654) name(655) \
    name(656) name(657) name(658) name(659) name(660) name(661) name(662) name(663) \
    name(664) name(665) name(666) name(667) name(668) name(669) name(670) name(671) \
    name(672) name(673) name(674) name(675) name(676) name(677) name(678) name(679) \
    name(680) name(681) name(682) name(683) name(684) name(685) name(686) name(687) \
    name(688) name(689) name(690) name(691) name(692) name(693) name(694) name(695) \
    name(696) name(697) name(698) name(699) \
    name(700) name(701) name(702) name(703) name(704) name(705) name(706) name(707) \
    name(708) name(709) name(710) name(711) name(712) name(713) name(714) name(715) \
    name(716) name(717) name(718) name(719) name(720) name(721) name(722) name(723) \
    name(724) name(725) name(726) name(727) name(728) name(729) name(730) name(731) \
    name(732) name(733) name(734) name(735) name(736) name(737) name(738) name(739) \
    name(740) name(741) name(742) name(743) name(744) name(745) name(746) name(747) \
    name(748) name(749) name(750) name(751) name(752) name(753) name(754) name(755) \
    name(756) name(757) name(758) name(759) name(760) name(761) name(762) name(763) \
    name(764) name(765) name(766) name(767)
#else
#define GL_EXTENSION_LIST(name) \
    name(0)   name(1)   name(2)   name(3)   name(4)   name(5)   name(6)   name(7)  \
    name(8)   name(9)   name(10)  name(11)  name(12)  name(13)  name(14)  name(15) \
    name(16)  name(17)  name(18)  name(19)  name(20)  name(21)  name(22)  name(23) \
    name(24)  name(25)  name(26)  name(27)  name(28)  name(29)  name(30)  name(31) \
    name(32)  name(33)  name(34)  name(35)  name(36)  name(37)  name(38)  name(39) \
    name(40)  name(41)  name(42)  name(43)  name(44)  name(45)  name(46)  name(47) \
    name(48)  name(49)  name(50)  name(51)  name(52)  name(53)  name(54)  name(55) \
    name(56)  name(57)  name(58)  name(59)  name(60)  name(61)  name(62)  name(63) \
    name(64)  name(65)  name(66)  name(67)  name(68)  name(69)  name(70)  name(71) \
    name(72)  name(73)  name(74)  name(75)  name(76)  name(77)  name(78)  name(79) \
    name(80)  name(81)  name(82)  name(83)  name(84)  name(85)  name(86)  name(87) \
    name(88)  name(89)  name(90)  name(91)  name(92)  name(93)  name(94)  name(95) \
    name(96)  name(97)  name(98)  name(99)  \
    name(100) name(101) name(102) name(103) name(104) name(105) name(106) name(107) \
    name(108) name(109) name(110) name(111) name(112) name(113) name(114) name(115) \
    name(116) name(117) name(118) name(119) name(120) name(121) name(122) name(123) \
    name(124) name(125) name(126) name(127) name(128) name(129) name(130) name(131) \
    name(132) name(133) name(134) name(135) name(136) name(137) name(138) name(139) \
    name(140) name(141) name(142) name(143) name(144) name(145) name(146) name(147) \
    name(148) name(149) name(150) name(151) name(152) name(153) name(154) name(155) \
    name(156) name(157) name(158) name(159) name(160) name(161) name(162) name(163) \
    name(164) name(165) name(166) name(167) name(168) name(169) name(170) name(171) \
    name(172) name(173) name(174) name(175) name(176) name(177) name(178) name(179) \
    name(180) name(181) name(182) name(183) name(184) name(185) name(186) name(187) \
    name(188) name(189) name(190) name(191) name(192) name(193) name(194) name(195) \
    name(196) name(197) name(198) name(199) \
    name(200) name(201) name(202) name(203) name(204) name(205) name(206) name(207) \
    name(208) name(209) name(210) name(211) name(212) name(213) name(214) name(215) \
    name(216) name(217) name(218) name(219) name(220) name(221) name(222) name(223) \
    name(224) name(225) name(226) name(227) name(228) name(229) name(230) name(231) \
    name(232) name(233) name(234) name(235) name(236) name(237) name(238) name(239) \
    name(240) name(241) name(242) name(243) name(244) name(245) name(246) name(247) \
    name(248) name(249) name(250) name(251) name(252) name(253) name(254) name(255)
#endif


GL_EXTENSION_LIST( GL_EXTENSION )

#define GL_EXTENSION_ARRAY(_n)  GL_EXTENSION_NAME(_n),

extern const __eglMustCastToProperFunctionPointerType gExtensionForwarders[MAX_NUMBER_OF_GL_EXTENSIONS] = {
        GL_EXTENSION_LIST( GL_EXTENSION_ARRAY )
 };

#undef GET_TLS
#undef GL_EXTENSION_LIST
#undef GL_EXTENSION_ARRAY
#undef GL_EXTENSION_NAME
#undef GL_EXTENSION
#undef API_ENTRY
#undef CALL_GL_EXTENSION_API

// ----------------------------------------------------------------------------
}; // namespace android
// ----------------------------------------------------------------------------

