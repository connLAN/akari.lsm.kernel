/*
 * editpolicy_keyword.c
 *
 * AKARI's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0-pre   2010/08/01
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License v2 as published by the
 * Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */
#include "akaritools.h"
#include "editpolicy.h"

/* Vakaribles */

struct akari_editpolicy_directive akari_directives[AKARI_MAX_DIRECTIVE_INDEX] = {
	[AKARI_DIRECTIVE_ACL_GROUP_000]                 = { "acl_group 0", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_001]                 = { "acl_group 1", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_002]                 = { "acl_group 2", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_003]                 = { "acl_group 3", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_004]                 = { "acl_group 4", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_005]                 = { "acl_group 5", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_006]                 = { "acl_group 6", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_007]                 = { "acl_group 7", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_008]                 = { "acl_group 8", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_009]                 = { "acl_group 9", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_010]                 = { "acl_group 10", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_011]                 = { "acl_group 11", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_012]                 = { "acl_group 12", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_013]                 = { "acl_group 13", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_014]                 = { "acl_group 14", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_015]                 = { "acl_group 15", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_016]                 = { "acl_group 16", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_017]                 = { "acl_group 17", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_018]                 = { "acl_group 18", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_019]                 = { "acl_group 19", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_020]                 = { "acl_group 20", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_021]                 = { "acl_group 21", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_022]                 = { "acl_group 22", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_023]                 = { "acl_group 23", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_024]                 = { "acl_group 24", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_025]                 = { "acl_group 25", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_026]                 = { "acl_group 26", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_027]                 = { "acl_group 27", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_028]                 = { "acl_group 28", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_029]                 = { "acl_group 29", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_030]                 = { "acl_group 30", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_031]                 = { "acl_group 31", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_032]                 = { "acl_group 32", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_033]                 = { "acl_group 33", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_034]                 = { "acl_group 34", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_035]                 = { "acl_group 35", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_036]                 = { "acl_group 36", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_037]                 = { "acl_group 37", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_038]                 = { "acl_group 38", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_039]                 = { "acl_group 39", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_040]                 = { "acl_group 40", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_041]                 = { "acl_group 41", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_042]                 = { "acl_group 42", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_043]                 = { "acl_group 43", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_044]                 = { "acl_group 44", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_045]                 = { "acl_group 45", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_046]                 = { "acl_group 46", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_047]                 = { "acl_group 47", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_048]                 = { "acl_group 48", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_049]                 = { "acl_group 49", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_050]                 = { "acl_group 50", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_051]                 = { "acl_group 51", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_052]                 = { "acl_group 52", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_053]                 = { "acl_group 53", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_054]                 = { "acl_group 54", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_055]                 = { "acl_group 55", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_056]                 = { "acl_group 56", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_057]                 = { "acl_group 57", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_058]                 = { "acl_group 58", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_059]                 = { "acl_group 59", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_060]                 = { "acl_group 60", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_061]                 = { "acl_group 61", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_062]                 = { "acl_group 62", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_063]                 = { "acl_group 63", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_064]                 = { "acl_group 64", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_065]                 = { "acl_group 65", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_066]                 = { "acl_group 66", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_067]                 = { "acl_group 67", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_068]                 = { "acl_group 68", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_069]                 = { "acl_group 69", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_070]                 = { "acl_group 70", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_071]                 = { "acl_group 71", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_072]                 = { "acl_group 72", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_073]                 = { "acl_group 73", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_074]                 = { "acl_group 74", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_075]                 = { "acl_group 75", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_076]                 = { "acl_group 76", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_077]                 = { "acl_group 77", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_078]                 = { "acl_group 78", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_079]                 = { "acl_group 79", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_080]                 = { "acl_group 80", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_081]                 = { "acl_group 81", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_082]                 = { "acl_group 82", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_083]                 = { "acl_group 83", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_084]                 = { "acl_group 84", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_085]                 = { "acl_group 85", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_086]                 = { "acl_group 86", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_087]                 = { "acl_group 87", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_088]                 = { "acl_group 88", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_089]                 = { "acl_group 89", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_090]                 = { "acl_group 90", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_091]                 = { "acl_group 91", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_092]                 = { "acl_group 92", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_093]                 = { "acl_group 93", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_094]                 = { "acl_group 94", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_095]                 = { "acl_group 95", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_096]                 = { "acl_group 96", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_097]                 = { "acl_group 97", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_098]                 = { "acl_group 98", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_099]                 = { "acl_group 99", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_100]                 = { "acl_group 100", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_101]                 = { "acl_group 101", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_102]                 = { "acl_group 102", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_103]                 = { "acl_group 103", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_104]                 = { "acl_group 104", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_105]                 = { "acl_group 105", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_106]                 = { "acl_group 106", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_107]                 = { "acl_group 107", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_108]                 = { "acl_group 108", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_109]                 = { "acl_group 109", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_110]                 = { "acl_group 110", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_111]                 = { "acl_group 111", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_112]                 = { "acl_group 112", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_113]                 = { "acl_group 113", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_114]                 = { "acl_group 114", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_115]                 = { "acl_group 115", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_116]                 = { "acl_group 116", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_117]                 = { "acl_group 117", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_118]                 = { "acl_group 118", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_119]                 = { "acl_group 119", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_120]                 = { "acl_group 120", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_121]                 = { "acl_group 121", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_122]                 = { "acl_group 122", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_123]                 = { "acl_group 123", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_124]                 = { "acl_group 124", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_125]                 = { "acl_group 125", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_126]                 = { "acl_group 126", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_127]                 = { "acl_group 127", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_128]                 = { "acl_group 128", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_129]                 = { "acl_group 129", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_130]                 = { "acl_group 130", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_131]                 = { "acl_group 131", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_132]                 = { "acl_group 132", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_133]                 = { "acl_group 133", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_134]                 = { "acl_group 134", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_135]                 = { "acl_group 135", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_136]                 = { "acl_group 136", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_137]                 = { "acl_group 137", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_138]                 = { "acl_group 138", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_139]                 = { "acl_group 139", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_140]                 = { "acl_group 140", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_141]                 = { "acl_group 141", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_142]                 = { "acl_group 142", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_143]                 = { "acl_group 143", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_144]                 = { "acl_group 144", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_145]                 = { "acl_group 145", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_146]                 = { "acl_group 146", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_147]                 = { "acl_group 147", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_148]                 = { "acl_group 148", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_149]                 = { "acl_group 149", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_150]                 = { "acl_group 150", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_151]                 = { "acl_group 151", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_152]                 = { "acl_group 152", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_153]                 = { "acl_group 153", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_154]                 = { "acl_group 154", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_155]                 = { "acl_group 155", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_156]                 = { "acl_group 156", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_157]                 = { "acl_group 157", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_158]                 = { "acl_group 158", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_159]                 = { "acl_group 159", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_160]                 = { "acl_group 160", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_161]                 = { "acl_group 161", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_162]                 = { "acl_group 162", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_163]                 = { "acl_group 163", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_164]                 = { "acl_group 164", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_165]                 = { "acl_group 165", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_166]                 = { "acl_group 166", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_167]                 = { "acl_group 167", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_168]                 = { "acl_group 168", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_169]                 = { "acl_group 169", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_170]                 = { "acl_group 170", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_171]                 = { "acl_group 171", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_172]                 = { "acl_group 172", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_173]                 = { "acl_group 173", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_174]                 = { "acl_group 174", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_175]                 = { "acl_group 175", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_176]                 = { "acl_group 176", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_177]                 = { "acl_group 177", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_178]                 = { "acl_group 178", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_179]                 = { "acl_group 179", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_180]                 = { "acl_group 180", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_181]                 = { "acl_group 181", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_182]                 = { "acl_group 182", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_183]                 = { "acl_group 183", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_184]                 = { "acl_group 184", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_185]                 = { "acl_group 185", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_186]                 = { "acl_group 186", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_187]                 = { "acl_group 187", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_188]                 = { "acl_group 188", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_189]                 = { "acl_group 189", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_190]                 = { "acl_group 190", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_191]                 = { "acl_group 191", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_192]                 = { "acl_group 192", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_193]                 = { "acl_group 193", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_194]                 = { "acl_group 194", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_195]                 = { "acl_group 195", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_196]                 = { "acl_group 196", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_197]                 = { "acl_group 197", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_198]                 = { "acl_group 198", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_199]                 = { "acl_group 199", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_200]                 = { "acl_group 200", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_201]                 = { "acl_group 201", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_202]                 = { "acl_group 202", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_203]                 = { "acl_group 203", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_204]                 = { "acl_group 204", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_205]                 = { "acl_group 205", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_206]                 = { "acl_group 206", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_207]                 = { "acl_group 207", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_208]                 = { "acl_group 208", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_209]                 = { "acl_group 209", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_210]                 = { "acl_group 210", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_211]                 = { "acl_group 211", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_212]                 = { "acl_group 212", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_213]                 = { "acl_group 213", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_214]                 = { "acl_group 214", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_215]                 = { "acl_group 215", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_216]                 = { "acl_group 216", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_217]                 = { "acl_group 217", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_218]                 = { "acl_group 218", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_219]                 = { "acl_group 219", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_220]                 = { "acl_group 220", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_221]                 = { "acl_group 221", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_222]                 = { "acl_group 222", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_223]                 = { "acl_group 223", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_224]                 = { "acl_group 224", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_225]                 = { "acl_group 225", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_226]                 = { "acl_group 226", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_227]                 = { "acl_group 227", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_228]                 = { "acl_group 228", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_229]                 = { "acl_group 229", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_230]                 = { "acl_group 230", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_231]                 = { "acl_group 231", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_232]                 = { "acl_group 232", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_233]                 = { "acl_group 233", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_234]                 = { "acl_group 234", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_235]                 = { "acl_group 235", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_236]                 = { "acl_group 236", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_237]                 = { "acl_group 237", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_238]                 = { "acl_group 238", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_239]                 = { "acl_group 239", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_240]                 = { "acl_group 240", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_241]                 = { "acl_group 241", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_242]                 = { "acl_group 242", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_243]                 = { "acl_group 243", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_244]                 = { "acl_group 244", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_245]                 = { "acl_group 245", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_246]                 = { "acl_group 246", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_247]                 = { "acl_group 247", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_248]                 = { "acl_group 248", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_249]                 = { "acl_group 249", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_250]                 = { "acl_group 250", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_251]                 = { "acl_group 251", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_252]                 = { "acl_group 252", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_253]                 = { "acl_group 253", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_254]                 = { "acl_group 254", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ACL_GROUP_255]                 = { "acl_group 255", NULL, 0, 0 },
	[AKARI_DIRECTIVE_ADDRESS_GROUP]                 = { "address_group", NULL, 0, 0 },
	[AKARI_DIRECTIVE_AGGREGATOR]                    = { "aggregator", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_APPEND]                   = { "file append", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_CHGRP]                    = { "file chgrp", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_CHMOD]                    = { "file chmod", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_CHOWN]                    = { "file chown", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_CHROOT]                   = { "file chroot", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_CREATE]                   = { "file create", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_EXECUTE]                  = { "file execute", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_IOCTL]                    = { "file ioctl", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_LINK]                     = { "file link", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_MKBLOCK]                  = { "file mkblock", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_MKCHAR]                   = { "file mkchar", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_MKDIR]                    = { "file mkdir", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_MKFIFO]                   = { "file mkfifo", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_MKSOCK]                   = { "file mksock", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_MOUNT]                    = { "file mount", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_PATTERN]                  = { "file_pattern", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_PIVOT_ROOT]               = { "file pivot_root", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_READ]                     = { "file read", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_RENAME]                   = { "file rename", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_RMDIR]                    = { "file rmdir", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_SYMLINK]                  = { "file symlink", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_TRANSIT]                  = { "file transit", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_TRUNCATE]                 = { "file truncate", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_UNLINK]                   = { "file unlink", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_UNMOUNT]                  = { "file unmount", NULL, 0, 0 },
	[AKARI_DIRECTIVE_FILE_WRITE]                    = { "file write", NULL, 0, 0 },
	[AKARI_DIRECTIVE_INITIALIZE_DOMAIN]             = { "initialize_domain", NULL, 0, 0 },
	[AKARI_DIRECTIVE_KEEP_DOMAIN]                   = { "keep_domain", NULL, 0, 0 },
	[AKARI_DIRECTIVE_MISC_ENV]                      = { "misc env", NULL, 0, 0 },
	[AKARI_DIRECTIVE_NETWORK_INET]                  = { "network inet", NULL, 0, 0 },
	[AKARI_DIRECTIVE_NETWORK_UNIX]                  = { "network unix", NULL, 0, 0 },
	[AKARI_DIRECTIVE_NONE]                          = { "", NULL, 0, 0 },
	[AKARI_DIRECTIVE_NO_INITIALIZE_DOMAIN]          = { "no_initialize_domain", NULL, 0, 0 },
	[AKARI_DIRECTIVE_NO_KEEP_DOMAIN]                = { "no_keep_domain", NULL, 0, 0 },
	[AKARI_DIRECTIVE_NUMBER_GROUP]                  = { "number_group", NULL, 0, 0 },
	[AKARI_DIRECTIVE_PATH_GROUP]                    = { "path_group", NULL, 0, 0 },
	[AKARI_DIRECTIVE_QUOTA_EXCEEDED]                = { "quota_exceeded", NULL, 0, 0 },
	[AKARI_DIRECTIVE_TASK_AUTO_DOMAIN_TRANSITION]   = { "task auto_domain_transition", NULL, 0, 0 },
	[AKARI_DIRECTIVE_TASK_MANUAL_DOMAIN_TRANSITION] = { "task manual_domain_transition", NULL, 0, 0 },
	[AKARI_DIRECTIVE_TRANSITION_FAILED]             = { "transition_failed", NULL, 0, 0 },
	[AKARI_DIRECTIVE_USE_GROUP]                     = { "use_group", NULL, 0, 0 },
	[AKARI_DIRECTIVE_USE_PROFILE]                   = { "use_profile", NULL, 0, 0 },
};

/* Main functions */

u16 akari_find_directive(const _Bool forward, char *line)
{
	u16 i;
	for (i = 1; i < AKARI_MAX_DIRECTIVE_INDEX; i++) {
		if (forward) {
			const int len = akari_directives[i].original_len;
			if (strncmp(line, akari_directives[i].original, len) ||
			    (line[len] != ' ' && line[len]))
				continue;
			if (line[len])
				memmove(line, line + len + 1,
					strlen(line + len + 1) + 1);
			else
				line[0] = '\0';
			return i;
		} else {
			const int len = akari_directives[i].alias_len;
			if (strncmp(line, akari_directives[i].alias, len) ||
			    (line[len] != ' ' && line[len]))
				continue;
			if (line[len])
				memmove(line, line + len + 1,
					strlen(line + len + 1) + 1);
			else
				line[0] = '\0';
			return i;
		}
	}
	return AKARI_DIRECTIVE_NONE;
}

void akari_editpolicy_init_keyword_map(void)
{
	FILE *fp = fopen(AKARI_CONFIG_FILE, "r");
	int i;
	if (!fp)
		goto use_default;
	akari_get();
	while (true) {
		char *line = akari_freadline(fp);
		char *cp;
		if (!line)
			break;
		if (!akari_str_starts(line, "editpolicy.keyword_alias "))
			continue;
		cp = strchr(line, '=');
		if (!cp)
			continue;
		*cp++ = '\0';
		akari_normalize_line(line);
		akari_normalize_line(cp);
		if (!*line || !*cp)
			continue;
		for (i = 1; i < AKARI_MAX_DIRECTIVE_INDEX; i++) {
			if (strcmp(line, akari_directives[i].original))
				continue;
			free((void *) akari_directives[i].alias);
			cp = strdup(cp);
			if (!cp)
				akari_out_of_memory();
			akari_directives[i].alias = cp;
			akari_directives[i].alias_len = strlen(cp);
			break;
		}
	}
	akari_put();
	fclose(fp);
use_default:
	for (i = 1; i < AKARI_MAX_DIRECTIVE_INDEX; i++) {
		if (!akari_directives[i].alias)
			akari_directives[i].alias = akari_directives[i].original;
		akari_directives[i].original_len = strlen(akari_directives[i].original);
		akari_directives[i].alias_len = strlen(akari_directives[i].alias);
	}
}
