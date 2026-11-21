//! Validation of the emoji of a reaction.
//!
//! An emoji is one extended grapheme cluster (UAX #29), at most
//! [`MAX_EMOJI_BYTES`] bytes, whose first scalar is `Extended_Pictographic`,
//! or a regional-indicator pair (flag), or a keycap (`[0-9#*]`, optional
//! U+FE0F, U+20E3). No list of known emoji: a newer peer's emoji must not be
//! quarantined here.

use unicode_segmentation::UnicodeSegmentation;

use crate::{CoreError, Result};

/// Most emoji one person can hold on one message.
pub const MAX_REACTIONS: usize = 20;
/// Largest emoji, in bytes (a family ZWJ sequence is 25).
pub const MAX_EMOJI_BYTES: usize = 32;

/// `Extended_Pictographic` ranges, from Unicode 17.0.0 `emoji-data.txt`
/// (the version of `unicode_segmentation::UNICODE_VERSION`), sorted. The
/// crate keeps its own table private, hence this copy; a test checks it
/// against the crate's segmentation.
const EXTENDED_PICTOGRAPHIC: &[(char, char)] = &[
    ('\u{a9}', '\u{a9}'),
    ('\u{ae}', '\u{ae}'),
    ('\u{203c}', '\u{203c}'),
    ('\u{2049}', '\u{2049}'),
    ('\u{2122}', '\u{2122}'),
    ('\u{2139}', '\u{2139}'),
    ('\u{2194}', '\u{2199}'),
    ('\u{21a9}', '\u{21aa}'),
    ('\u{231a}', '\u{231b}'),
    ('\u{2328}', '\u{2328}'),
    ('\u{23cf}', '\u{23cf}'),
    ('\u{23e9}', '\u{23ec}'),
    ('\u{23ed}', '\u{23ee}'),
    ('\u{23ef}', '\u{23ef}'),
    ('\u{23f0}', '\u{23f0}'),
    ('\u{23f1}', '\u{23f2}'),
    ('\u{23f3}', '\u{23f3}'),
    ('\u{23f8}', '\u{23fa}'),
    ('\u{24c2}', '\u{24c2}'),
    ('\u{25aa}', '\u{25ab}'),
    ('\u{25b6}', '\u{25b6}'),
    ('\u{25c0}', '\u{25c0}'),
    ('\u{25fb}', '\u{25fe}'),
    ('\u{2600}', '\u{2601}'),
    ('\u{2602}', '\u{2603}'),
    ('\u{2604}', '\u{2604}'),
    ('\u{260e}', '\u{260e}'),
    ('\u{2611}', '\u{2611}'),
    ('\u{2614}', '\u{2615}'),
    ('\u{2618}', '\u{2618}'),
    ('\u{261d}', '\u{261d}'),
    ('\u{2620}', '\u{2620}'),
    ('\u{2622}', '\u{2623}'),
    ('\u{2626}', '\u{2626}'),
    ('\u{262a}', '\u{262a}'),
    ('\u{262e}', '\u{262e}'),
    ('\u{262f}', '\u{262f}'),
    ('\u{2638}', '\u{2639}'),
    ('\u{263a}', '\u{263a}'),
    ('\u{2640}', '\u{2640}'),
    ('\u{2642}', '\u{2642}'),
    ('\u{2648}', '\u{2653}'),
    ('\u{265f}', '\u{265f}'),
    ('\u{2660}', '\u{2660}'),
    ('\u{2663}', '\u{2663}'),
    ('\u{2665}', '\u{2666}'),
    ('\u{2668}', '\u{2668}'),
    ('\u{267b}', '\u{267b}'),
    ('\u{267e}', '\u{267e}'),
    ('\u{267f}', '\u{267f}'),
    ('\u{2692}', '\u{2692}'),
    ('\u{2693}', '\u{2693}'),
    ('\u{2694}', '\u{2694}'),
    ('\u{2695}', '\u{2695}'),
    ('\u{2696}', '\u{2697}'),
    ('\u{2699}', '\u{2699}'),
    ('\u{269b}', '\u{269c}'),
    ('\u{26a0}', '\u{26a1}'),
    ('\u{26a7}', '\u{26a7}'),
    ('\u{26aa}', '\u{26ab}'),
    ('\u{26b0}', '\u{26b1}'),
    ('\u{26bd}', '\u{26be}'),
    ('\u{26c4}', '\u{26c5}'),
    ('\u{26c8}', '\u{26c8}'),
    ('\u{26ce}', '\u{26ce}'),
    ('\u{26cf}', '\u{26cf}'),
    ('\u{26d1}', '\u{26d1}'),
    ('\u{26d3}', '\u{26d3}'),
    ('\u{26d4}', '\u{26d4}'),
    ('\u{26e9}', '\u{26e9}'),
    ('\u{26ea}', '\u{26ea}'),
    ('\u{26f0}', '\u{26f1}'),
    ('\u{26f2}', '\u{26f3}'),
    ('\u{26f4}', '\u{26f4}'),
    ('\u{26f5}', '\u{26f5}'),
    ('\u{26f7}', '\u{26f9}'),
    ('\u{26fa}', '\u{26fa}'),
    ('\u{26fd}', '\u{26fd}'),
    ('\u{2702}', '\u{2702}'),
    ('\u{2705}', '\u{2705}'),
    ('\u{2708}', '\u{270c}'),
    ('\u{270d}', '\u{270d}'),
    ('\u{270f}', '\u{270f}'),
    ('\u{2712}', '\u{2712}'),
    ('\u{2714}', '\u{2714}'),
    ('\u{2716}', '\u{2716}'),
    ('\u{271d}', '\u{271d}'),
    ('\u{2721}', '\u{2721}'),
    ('\u{2728}', '\u{2728}'),
    ('\u{2733}', '\u{2734}'),
    ('\u{2744}', '\u{2744}'),
    ('\u{2747}', '\u{2747}'),
    ('\u{274c}', '\u{274c}'),
    ('\u{274e}', '\u{274e}'),
    ('\u{2753}', '\u{2755}'),
    ('\u{2757}', '\u{2757}'),
    ('\u{2763}', '\u{2763}'),
    ('\u{2764}', '\u{2764}'),
    ('\u{2795}', '\u{2797}'),
    ('\u{27a1}', '\u{27a1}'),
    ('\u{27b0}', '\u{27b0}'),
    ('\u{27bf}', '\u{27bf}'),
    ('\u{2934}', '\u{2935}'),
    ('\u{2b05}', '\u{2b07}'),
    ('\u{2b1b}', '\u{2b1c}'),
    ('\u{2b50}', '\u{2b50}'),
    ('\u{2b55}', '\u{2b55}'),
    ('\u{3030}', '\u{3030}'),
    ('\u{303d}', '\u{303d}'),
    ('\u{3297}', '\u{3297}'),
    ('\u{3299}', '\u{3299}'),
    ('\u{1f004}', '\u{1f004}'),
    ('\u{1f02c}', '\u{1f02f}'),
    ('\u{1f094}', '\u{1f09f}'),
    ('\u{1f0af}', '\u{1f0b0}'),
    ('\u{1f0c0}', '\u{1f0c0}'),
    ('\u{1f0cf}', '\u{1f0cf}'),
    ('\u{1f0d0}', '\u{1f0d0}'),
    ('\u{1f0f6}', '\u{1f0ff}'),
    ('\u{1f170}', '\u{1f171}'),
    ('\u{1f17e}', '\u{1f17f}'),
    ('\u{1f18e}', '\u{1f18e}'),
    ('\u{1f191}', '\u{1f19a}'),
    ('\u{1f1ae}', '\u{1f1e5}'),
    ('\u{1f201}', '\u{1f202}'),
    ('\u{1f203}', '\u{1f20f}'),
    ('\u{1f21a}', '\u{1f21a}'),
    ('\u{1f22f}', '\u{1f22f}'),
    ('\u{1f232}', '\u{1f23a}'),
    ('\u{1f23c}', '\u{1f23f}'),
    ('\u{1f249}', '\u{1f24f}'),
    ('\u{1f250}', '\u{1f251}'),
    ('\u{1f252}', '\u{1f25f}'),
    ('\u{1f266}', '\u{1f2ff}'),
    ('\u{1f300}', '\u{1f30c}'),
    ('\u{1f30d}', '\u{1f30e}'),
    ('\u{1f30f}', '\u{1f30f}'),
    ('\u{1f310}', '\u{1f310}'),
    ('\u{1f311}', '\u{1f311}'),
    ('\u{1f312}', '\u{1f312}'),
    ('\u{1f313}', '\u{1f315}'),
    ('\u{1f316}', '\u{1f318}'),
    ('\u{1f319}', '\u{1f319}'),
    ('\u{1f31a}', '\u{1f31a}'),
    ('\u{1f31b}', '\u{1f31b}'),
    ('\u{1f31c}', '\u{1f31c}'),
    ('\u{1f31d}', '\u{1f31e}'),
    ('\u{1f31f}', '\u{1f320}'),
    ('\u{1f321}', '\u{1f321}'),
    ('\u{1f324}', '\u{1f32c}'),
    ('\u{1f32d}', '\u{1f32f}'),
    ('\u{1f330}', '\u{1f331}'),
    ('\u{1f332}', '\u{1f333}'),
    ('\u{1f334}', '\u{1f335}'),
    ('\u{1f336}', '\u{1f336}'),
    ('\u{1f337}', '\u{1f34a}'),
    ('\u{1f34b}', '\u{1f34b}'),
    ('\u{1f34c}', '\u{1f34f}'),
    ('\u{1f350}', '\u{1f350}'),
    ('\u{1f351}', '\u{1f37b}'),
    ('\u{1f37c}', '\u{1f37c}'),
    ('\u{1f37d}', '\u{1f37d}'),
    ('\u{1f37e}', '\u{1f37f}'),
    ('\u{1f380}', '\u{1f393}'),
    ('\u{1f396}', '\u{1f397}'),
    ('\u{1f399}', '\u{1f39b}'),
    ('\u{1f39e}', '\u{1f39f}'),
    ('\u{1f3a0}', '\u{1f3c4}'),
    ('\u{1f3c5}', '\u{1f3c5}'),
    ('\u{1f3c6}', '\u{1f3c6}'),
    ('\u{1f3c7}', '\u{1f3c7}'),
    ('\u{1f3c8}', '\u{1f3c8}'),
    ('\u{1f3c9}', '\u{1f3c9}'),
    ('\u{1f3ca}', '\u{1f3ca}'),
    ('\u{1f3cb}', '\u{1f3ce}'),
    ('\u{1f3cf}', '\u{1f3d3}'),
    ('\u{1f3d4}', '\u{1f3df}'),
    ('\u{1f3e0}', '\u{1f3e3}'),
    ('\u{1f3e4}', '\u{1f3e4}'),
    ('\u{1f3e5}', '\u{1f3f0}'),
    ('\u{1f3f3}', '\u{1f3f3}'),
    ('\u{1f3f4}', '\u{1f3f4}'),
    ('\u{1f3f5}', '\u{1f3f5}'),
    ('\u{1f3f7}', '\u{1f3f7}'),
    ('\u{1f3f8}', '\u{1f3fa}'),
    ('\u{1f400}', '\u{1f407}'),
    ('\u{1f408}', '\u{1f408}'),
    ('\u{1f409}', '\u{1f40b}'),
    ('\u{1f40c}', '\u{1f40e}'),
    ('\u{1f40f}', '\u{1f410}'),
    ('\u{1f411}', '\u{1f412}'),
    ('\u{1f413}', '\u{1f413}'),
    ('\u{1f414}', '\u{1f414}'),
    ('\u{1f415}', '\u{1f415}'),
    ('\u{1f416}', '\u{1f416}'),
    ('\u{1f417}', '\u{1f429}'),
    ('\u{1f42a}', '\u{1f42a}'),
    ('\u{1f42b}', '\u{1f43e}'),
    ('\u{1f43f}', '\u{1f43f}'),
    ('\u{1f440}', '\u{1f440}'),
    ('\u{1f441}', '\u{1f441}'),
    ('\u{1f442}', '\u{1f464}'),
    ('\u{1f465}', '\u{1f465}'),
    ('\u{1f466}', '\u{1f46b}'),
    ('\u{1f46c}', '\u{1f46d}'),
    ('\u{1f46e}', '\u{1f4ac}'),
    ('\u{1f4ad}', '\u{1f4ad}'),
    ('\u{1f4ae}', '\u{1f4b5}'),
    ('\u{1f4b6}', '\u{1f4b7}'),
    ('\u{1f4b8}', '\u{1f4eb}'),
    ('\u{1f4ec}', '\u{1f4ed}'),
    ('\u{1f4ee}', '\u{1f4ee}'),
    ('\u{1f4ef}', '\u{1f4ef}'),
    ('\u{1f4f0}', '\u{1f4f4}'),
    ('\u{1f4f5}', '\u{1f4f5}'),
    ('\u{1f4f6}', '\u{1f4f7}'),
    ('\u{1f4f8}', '\u{1f4f8}'),
    ('\u{1f4f9}', '\u{1f4fc}'),
    ('\u{1f4fd}', '\u{1f4fd}'),
    ('\u{1f4ff}', '\u{1f502}'),
    ('\u{1f503}', '\u{1f503}'),
    ('\u{1f504}', '\u{1f507}'),
    ('\u{1f508}', '\u{1f508}'),
    ('\u{1f509}', '\u{1f509}'),
    ('\u{1f50a}', '\u{1f514}'),
    ('\u{1f515}', '\u{1f515}'),
    ('\u{1f516}', '\u{1f52b}'),
    ('\u{1f52c}', '\u{1f52d}'),
    ('\u{1f52e}', '\u{1f53d}'),
    ('\u{1f549}', '\u{1f54a}'),
    ('\u{1f54b}', '\u{1f54e}'),
    ('\u{1f550}', '\u{1f55b}'),
    ('\u{1f55c}', '\u{1f567}'),
    ('\u{1f56f}', '\u{1f570}'),
    ('\u{1f573}', '\u{1f579}'),
    ('\u{1f57a}', '\u{1f57a}'),
    ('\u{1f587}', '\u{1f587}'),
    ('\u{1f58a}', '\u{1f58d}'),
    ('\u{1f590}', '\u{1f590}'),
    ('\u{1f595}', '\u{1f596}'),
    ('\u{1f5a4}', '\u{1f5a4}'),
    ('\u{1f5a5}', '\u{1f5a5}'),
    ('\u{1f5a8}', '\u{1f5a8}'),
    ('\u{1f5b1}', '\u{1f5b2}'),
    ('\u{1f5bc}', '\u{1f5bc}'),
    ('\u{1f5c2}', '\u{1f5c4}'),
    ('\u{1f5d1}', '\u{1f5d3}'),
    ('\u{1f5dc}', '\u{1f5de}'),
    ('\u{1f5e1}', '\u{1f5e1}'),
    ('\u{1f5e3}', '\u{1f5e3}'),
    ('\u{1f5e8}', '\u{1f5e8}'),
    ('\u{1f5ef}', '\u{1f5ef}'),
    ('\u{1f5f3}', '\u{1f5f3}'),
    ('\u{1f5fa}', '\u{1f5fa}'),
    ('\u{1f5fb}', '\u{1f5ff}'),
    ('\u{1f600}', '\u{1f600}'),
    ('\u{1f601}', '\u{1f606}'),
    ('\u{1f607}', '\u{1f608}'),
    ('\u{1f609}', '\u{1f60d}'),
    ('\u{1f60e}', '\u{1f60e}'),
    ('\u{1f60f}', '\u{1f60f}'),
    ('\u{1f610}', '\u{1f610}'),
    ('\u{1f611}', '\u{1f611}'),
    ('\u{1f612}', '\u{1f614}'),
    ('\u{1f615}', '\u{1f615}'),
    ('\u{1f616}', '\u{1f616}'),
    ('\u{1f617}', '\u{1f617}'),
    ('\u{1f618}', '\u{1f618}'),
    ('\u{1f619}', '\u{1f619}'),
    ('\u{1f61a}', '\u{1f61a}'),
    ('\u{1f61b}', '\u{1f61b}'),
    ('\u{1f61c}', '\u{1f61e}'),
    ('\u{1f61f}', '\u{1f61f}'),
    ('\u{1f620}', '\u{1f625}'),
    ('\u{1f626}', '\u{1f627}'),
    ('\u{1f628}', '\u{1f62b}'),
    ('\u{1f62c}', '\u{1f62c}'),
    ('\u{1f62d}', '\u{1f62d}'),
    ('\u{1f62e}', '\u{1f62f}'),
    ('\u{1f630}', '\u{1f633}'),
    ('\u{1f634}', '\u{1f634}'),
    ('\u{1f635}', '\u{1f635}'),
    ('\u{1f636}', '\u{1f636}'),
    ('\u{1f637}', '\u{1f640}'),
    ('\u{1f641}', '\u{1f644}'),
    ('\u{1f645}', '\u{1f64f}'),
    ('\u{1f680}', '\u{1f680}'),
    ('\u{1f681}', '\u{1f682}'),
    ('\u{1f683}', '\u{1f685}'),
    ('\u{1f686}', '\u{1f686}'),
    ('\u{1f687}', '\u{1f687}'),
    ('\u{1f688}', '\u{1f688}'),
    ('\u{1f689}', '\u{1f689}'),
    ('\u{1f68a}', '\u{1f68b}'),
    ('\u{1f68c}', '\u{1f68c}'),
    ('\u{1f68d}', '\u{1f68d}'),
    ('\u{1f68e}', '\u{1f68e}'),
    ('\u{1f68f}', '\u{1f68f}'),
    ('\u{1f690}', '\u{1f690}'),
    ('\u{1f691}', '\u{1f693}'),
    ('\u{1f694}', '\u{1f694}'),
    ('\u{1f695}', '\u{1f695}'),
    ('\u{1f696}', '\u{1f696}'),
    ('\u{1f697}', '\u{1f697}'),
    ('\u{1f698}', '\u{1f698}'),
    ('\u{1f699}', '\u{1f69a}'),
    ('\u{1f69b}', '\u{1f6a1}'),
    ('\u{1f6a2}', '\u{1f6a2}'),
    ('\u{1f6a3}', '\u{1f6a3}'),
    ('\u{1f6a4}', '\u{1f6a5}'),
    ('\u{1f6a6}', '\u{1f6a6}'),
    ('\u{1f6a7}', '\u{1f6ad}'),
    ('\u{1f6ae}', '\u{1f6b1}'),
    ('\u{1f6b2}', '\u{1f6b2}'),
    ('\u{1f6b3}', '\u{1f6b5}'),
    ('\u{1f6b6}', '\u{1f6b6}'),
    ('\u{1f6b7}', '\u{1f6b8}'),
    ('\u{1f6b9}', '\u{1f6be}'),
    ('\u{1f6bf}', '\u{1f6bf}'),
    ('\u{1f6c0}', '\u{1f6c0}'),
    ('\u{1f6c1}', '\u{1f6c5}'),
    ('\u{1f6cb}', '\u{1f6cb}'),
    ('\u{1f6cc}', '\u{1f6cc}'),
    ('\u{1f6cd}', '\u{1f6cf}'),
    ('\u{1f6d0}', '\u{1f6d0}'),
    ('\u{1f6d1}', '\u{1f6d2}'),
    ('\u{1f6d5}', '\u{1f6d5}'),
    ('\u{1f6d6}', '\u{1f6d7}'),
    ('\u{1f6d8}', '\u{1f6d8}'),
    ('\u{1f6d9}', '\u{1f6db}'),
    ('\u{1f6dc}', '\u{1f6dc}'),
    ('\u{1f6dd}', '\u{1f6df}'),
    ('\u{1f6e0}', '\u{1f6e5}'),
    ('\u{1f6e9}', '\u{1f6e9}'),
    ('\u{1f6eb}', '\u{1f6ec}'),
    ('\u{1f6ed}', '\u{1f6ef}'),
    ('\u{1f6f0}', '\u{1f6f0}'),
    ('\u{1f6f3}', '\u{1f6f3}'),
    ('\u{1f6f4}', '\u{1f6f6}'),
    ('\u{1f6f7}', '\u{1f6f8}'),
    ('\u{1f6f9}', '\u{1f6f9}'),
    ('\u{1f6fa}', '\u{1f6fa}'),
    ('\u{1f6fb}', '\u{1f6fc}'),
    ('\u{1f6fd}', '\u{1f6ff}'),
    ('\u{1f7da}', '\u{1f7df}'),
    ('\u{1f7e0}', '\u{1f7eb}'),
    ('\u{1f7ec}', '\u{1f7ef}'),
    ('\u{1f7f0}', '\u{1f7f0}'),
    ('\u{1f7f1}', '\u{1f7ff}'),
    ('\u{1f80c}', '\u{1f80f}'),
    ('\u{1f848}', '\u{1f84f}'),
    ('\u{1f85a}', '\u{1f85f}'),
    ('\u{1f888}', '\u{1f88f}'),
    ('\u{1f8ae}', '\u{1f8af}'),
    ('\u{1f8bc}', '\u{1f8bf}'),
    ('\u{1f8c2}', '\u{1f8cf}'),
    ('\u{1f8d9}', '\u{1f8ff}'),
    ('\u{1f90c}', '\u{1f90c}'),
    ('\u{1f90d}', '\u{1f90f}'),
    ('\u{1f910}', '\u{1f918}'),
    ('\u{1f919}', '\u{1f91e}'),
    ('\u{1f91f}', '\u{1f91f}'),
    ('\u{1f920}', '\u{1f927}'),
    ('\u{1f928}', '\u{1f92f}'),
    ('\u{1f930}', '\u{1f930}'),
    ('\u{1f931}', '\u{1f932}'),
    ('\u{1f933}', '\u{1f93a}'),
    ('\u{1f93c}', '\u{1f93e}'),
    ('\u{1f93f}', '\u{1f93f}'),
    ('\u{1f940}', '\u{1f945}'),
    ('\u{1f947}', '\u{1f94b}'),
    ('\u{1f94c}', '\u{1f94c}'),
    ('\u{1f94d}', '\u{1f94f}'),
    ('\u{1f950}', '\u{1f95e}'),
    ('\u{1f95f}', '\u{1f96b}'),
    ('\u{1f96c}', '\u{1f970}'),
    ('\u{1f971}', '\u{1f971}'),
    ('\u{1f972}', '\u{1f972}'),
    ('\u{1f973}', '\u{1f976}'),
    ('\u{1f977}', '\u{1f978}'),
    ('\u{1f979}', '\u{1f979}'),
    ('\u{1f97a}', '\u{1f97a}'),
    ('\u{1f97b}', '\u{1f97b}'),
    ('\u{1f97c}', '\u{1f97f}'),
    ('\u{1f980}', '\u{1f984}'),
    ('\u{1f985}', '\u{1f991}'),
    ('\u{1f992}', '\u{1f997}'),
    ('\u{1f998}', '\u{1f9a2}'),
    ('\u{1f9a3}', '\u{1f9a4}'),
    ('\u{1f9a5}', '\u{1f9aa}'),
    ('\u{1f9ab}', '\u{1f9ad}'),
    ('\u{1f9ae}', '\u{1f9af}'),
    ('\u{1f9b0}', '\u{1f9b9}'),
    ('\u{1f9ba}', '\u{1f9bf}'),
    ('\u{1f9c0}', '\u{1f9c0}'),
    ('\u{1f9c1}', '\u{1f9c2}'),
    ('\u{1f9c3}', '\u{1f9ca}'),
    ('\u{1f9cb}', '\u{1f9cb}'),
    ('\u{1f9cc}', '\u{1f9cc}'),
    ('\u{1f9cd}', '\u{1f9cf}'),
    ('\u{1f9d0}', '\u{1f9e6}'),
    ('\u{1f9e7}', '\u{1f9ff}'),
    ('\u{1fa58}', '\u{1fa5f}'),
    ('\u{1fa6e}', '\u{1fa6f}'),
    ('\u{1fa70}', '\u{1fa73}'),
    ('\u{1fa74}', '\u{1fa74}'),
    ('\u{1fa75}', '\u{1fa77}'),
    ('\u{1fa78}', '\u{1fa7a}'),
    ('\u{1fa7b}', '\u{1fa7c}'),
    ('\u{1fa7d}', '\u{1fa7f}'),
    ('\u{1fa80}', '\u{1fa82}'),
    ('\u{1fa83}', '\u{1fa86}'),
    ('\u{1fa87}', '\u{1fa88}'),
    ('\u{1fa89}', '\u{1fa89}'),
    ('\u{1fa8a}', '\u{1fa8a}'),
    ('\u{1fa8b}', '\u{1fa8d}'),
    ('\u{1fa8e}', '\u{1fa8e}'),
    ('\u{1fa8f}', '\u{1fa8f}'),
    ('\u{1fa90}', '\u{1fa95}'),
    ('\u{1fa96}', '\u{1faa8}'),
    ('\u{1faa9}', '\u{1faac}'),
    ('\u{1faad}', '\u{1faaf}'),
    ('\u{1fab0}', '\u{1fab6}'),
    ('\u{1fab7}', '\u{1faba}'),
    ('\u{1fabb}', '\u{1fabd}'),
    ('\u{1fabe}', '\u{1fabe}'),
    ('\u{1fabf}', '\u{1fabf}'),
    ('\u{1fac0}', '\u{1fac2}'),
    ('\u{1fac3}', '\u{1fac5}'),
    ('\u{1fac6}', '\u{1fac6}'),
    ('\u{1fac7}', '\u{1fac7}'),
    ('\u{1fac8}', '\u{1fac8}'),
    ('\u{1fac9}', '\u{1facc}'),
    ('\u{1facd}', '\u{1facd}'),
    ('\u{1face}', '\u{1facf}'),
    ('\u{1fad0}', '\u{1fad6}'),
    ('\u{1fad7}', '\u{1fad9}'),
    ('\u{1fada}', '\u{1fadb}'),
    ('\u{1fadc}', '\u{1fadc}'),
    ('\u{1fadd}', '\u{1fade}'),
    ('\u{1fadf}', '\u{1fadf}'),
    ('\u{1fae0}', '\u{1fae7}'),
    ('\u{1fae8}', '\u{1fae8}'),
    ('\u{1fae9}', '\u{1fae9}'),
    ('\u{1faea}', '\u{1faea}'),
    ('\u{1faeb}', '\u{1faee}'),
    ('\u{1faef}', '\u{1faef}'),
    ('\u{1faf0}', '\u{1faf6}'),
    ('\u{1faf7}', '\u{1faf8}'),
    ('\u{1faf9}', '\u{1faff}'),
    ('\u{1fc00}', '\u{1fffd}'),
];

fn is_extended_pictographic(c: char) -> bool {
    in_table(EXTENDED_PICTOGRAPHIC, c)
}

fn is_regional_indicator(c: char) -> bool {
    ('\u{1F1E6}'..='\u{1F1FF}').contains(&c)
}

/// Is this single grapheme an emoji?
fn is_emoji_grapheme(g: &str) -> bool {
    let mut chars = g.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if is_extended_pictographic(first) {
        return true;
    }
    if is_regional_indicator(first) {
        return chars.next().is_some_and(is_regional_indicator) && chars.next().is_none();
    }
    if matches!(first, '0'..='9' | '#' | '*') {
        let mut next = chars.next();
        if next == Some('\u{FE0F}') {
            next = chars.next();
        }
        return next == Some('\u{20E3}') && chars.next().is_none();
    }
    false
}

/// `Ok` if `s` is exactly one emoji.
///
/// # Errors
/// [`CoreError::InvalidEmoji`] otherwise.
pub fn check_emoji(s: &str) -> Result<()> {
    if s.len() > MAX_EMOJI_BYTES {
        return Err(CoreError::InvalidEmoji);
    }
    let mut graphemes = s.graphemes(true);
    match (graphemes.next(), graphemes.next()) {
        (Some(g), None) if is_emoji_grapheme(g) => Ok(()),
        _ => Err(CoreError::InvalidEmoji),
    }
}

/// `Ok` if `emojis` is a valid reaction set: at most [`MAX_REACTIONS`], each
/// one valid, no duplicate.
///
/// # Errors
/// [`CoreError::TooManyEmoji`] past the limit, [`CoreError::InvalidEmoji`] for
/// an invalid emoji or a duplicate.
pub fn check_set(emojis: &[String]) -> Result<()> {
    if emojis.len() > MAX_REACTIONS {
        return Err(CoreError::TooManyEmoji);
    }
    for (i, e) in emojis.iter().enumerate() {
        check_emoji(e)?;
        if emojis[..i].contains(e) {
            return Err(CoreError::InvalidEmoji);
        }
    }
    Ok(())
}

/// Emoji whose default presentation is text (`Emoji=Yes` without
/// `Emoji_Presentation`), the keycap bases `[0-9#*]` excepted, from Unicode
/// emoji 16.0 `emoji-data.txt`, sorted. Since emoji 1.0 every new emoji has
/// the emoji presentation by default, so a newer one is never missing here.
const TEXT_DEFAULT: &[(char, char)] = &[
    ('\u{a9}', '\u{a9}'),
    ('\u{ae}', '\u{ae}'),
    ('\u{203c}', '\u{203c}'),
    ('\u{2049}', '\u{2049}'),
    ('\u{2122}', '\u{2122}'),
    ('\u{2139}', '\u{2139}'),
    ('\u{2194}', '\u{2199}'),
    ('\u{21a9}', '\u{21aa}'),
    ('\u{2328}', '\u{2328}'),
    ('\u{23cf}', '\u{23cf}'),
    ('\u{23ed}', '\u{23ef}'),
    ('\u{23f1}', '\u{23f2}'),
    ('\u{23f8}', '\u{23fa}'),
    ('\u{24c2}', '\u{24c2}'),
    ('\u{25aa}', '\u{25ab}'),
    ('\u{25b6}', '\u{25b6}'),
    ('\u{25c0}', '\u{25c0}'),
    ('\u{25fb}', '\u{25fc}'),
    ('\u{2600}', '\u{2604}'),
    ('\u{260e}', '\u{260e}'),
    ('\u{2611}', '\u{2611}'),
    ('\u{2618}', '\u{2618}'),
    ('\u{261d}', '\u{261d}'),
    ('\u{2620}', '\u{2620}'),
    ('\u{2622}', '\u{2623}'),
    ('\u{2626}', '\u{2626}'),
    ('\u{262a}', '\u{262a}'),
    ('\u{262e}', '\u{262f}'),
    ('\u{2638}', '\u{263a}'),
    ('\u{2640}', '\u{2640}'),
    ('\u{2642}', '\u{2642}'),
    ('\u{265f}', '\u{2660}'),
    ('\u{2663}', '\u{2663}'),
    ('\u{2665}', '\u{2666}'),
    ('\u{2668}', '\u{2668}'),
    ('\u{267b}', '\u{267b}'),
    ('\u{267e}', '\u{267e}'),
    ('\u{2692}', '\u{2692}'),
    ('\u{2694}', '\u{2697}'),
    ('\u{2699}', '\u{2699}'),
    ('\u{269b}', '\u{269c}'),
    ('\u{26a0}', '\u{26a0}'),
    ('\u{26a7}', '\u{26a7}'),
    ('\u{26b0}', '\u{26b1}'),
    ('\u{26c8}', '\u{26c8}'),
    ('\u{26cf}', '\u{26cf}'),
    ('\u{26d1}', '\u{26d1}'),
    ('\u{26d3}', '\u{26d3}'),
    ('\u{26e9}', '\u{26e9}'),
    ('\u{26f0}', '\u{26f1}'),
    ('\u{26f4}', '\u{26f4}'),
    ('\u{26f7}', '\u{26f9}'),
    ('\u{2702}', '\u{2702}'),
    ('\u{2708}', '\u{2709}'),
    ('\u{270c}', '\u{270d}'),
    ('\u{270f}', '\u{270f}'),
    ('\u{2712}', '\u{2712}'),
    ('\u{2714}', '\u{2714}'),
    ('\u{2716}', '\u{2716}'),
    ('\u{271d}', '\u{271d}'),
    ('\u{2721}', '\u{2721}'),
    ('\u{2733}', '\u{2734}'),
    ('\u{2744}', '\u{2744}'),
    ('\u{2747}', '\u{2747}'),
    ('\u{2763}', '\u{2764}'),
    ('\u{27a1}', '\u{27a1}'),
    ('\u{2934}', '\u{2935}'),
    ('\u{2b05}', '\u{2b07}'),
    ('\u{3030}', '\u{3030}'),
    ('\u{303d}', '\u{303d}'),
    ('\u{3297}', '\u{3297}'),
    ('\u{3299}', '\u{3299}'),
    ('\u{1f170}', '\u{1f171}'),
    ('\u{1f17e}', '\u{1f17f}'),
    ('\u{1f202}', '\u{1f202}'),
    ('\u{1f237}', '\u{1f237}'),
    ('\u{1f321}', '\u{1f321}'),
    ('\u{1f324}', '\u{1f32c}'),
    ('\u{1f336}', '\u{1f336}'),
    ('\u{1f37d}', '\u{1f37d}'),
    ('\u{1f396}', '\u{1f397}'),
    ('\u{1f399}', '\u{1f39b}'),
    ('\u{1f39e}', '\u{1f39f}'),
    ('\u{1f3cb}', '\u{1f3ce}'),
    ('\u{1f3d4}', '\u{1f3df}'),
    ('\u{1f3f3}', '\u{1f3f3}'),
    ('\u{1f3f5}', '\u{1f3f5}'),
    ('\u{1f3f7}', '\u{1f3f7}'),
    ('\u{1f43f}', '\u{1f43f}'),
    ('\u{1f441}', '\u{1f441}'),
    ('\u{1f4fd}', '\u{1f4fd}'),
    ('\u{1f549}', '\u{1f54a}'),
    ('\u{1f56f}', '\u{1f570}'),
    ('\u{1f573}', '\u{1f579}'),
    ('\u{1f587}', '\u{1f587}'),
    ('\u{1f58a}', '\u{1f58d}'),
    ('\u{1f590}', '\u{1f590}'),
    ('\u{1f5a5}', '\u{1f5a5}'),
    ('\u{1f5a8}', '\u{1f5a8}'),
    ('\u{1f5b1}', '\u{1f5b2}'),
    ('\u{1f5bc}', '\u{1f5bc}'),
    ('\u{1f5c2}', '\u{1f5c4}'),
    ('\u{1f5d1}', '\u{1f5d3}'),
    ('\u{1f5dc}', '\u{1f5de}'),
    ('\u{1f5e1}', '\u{1f5e1}'),
    ('\u{1f5e3}', '\u{1f5e3}'),
    ('\u{1f5e8}', '\u{1f5e8}'),
    ('\u{1f5ef}', '\u{1f5ef}'),
    ('\u{1f5f3}', '\u{1f5f3}'),
    ('\u{1f5fa}', '\u{1f5fa}'),
    ('\u{1f6cb}', '\u{1f6cb}'),
    ('\u{1f6cd}', '\u{1f6cf}'),
    ('\u{1f6e0}', '\u{1f6e5}'),
    ('\u{1f6e9}', '\u{1f6e9}'),
    ('\u{1f6f0}', '\u{1f6f0}'),
    ('\u{1f6f3}', '\u{1f6f3}'),
];

fn in_table(table: &[(char, char)], c: char) -> bool {
    table
        .binary_search_by(|&(lo, hi)| {
            if c < lo {
                core::cmp::Ordering::Greater
            } else if c > hi {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

fn is_modifier(c: char) -> bool {
    ('\u{1F3FB}'..='\u{1F3FF}').contains(&c)
}

/// The one spelling an emoji is stored, compared and sent in: its fully
/// qualified form (UTS #51). Every U+FE0F is dropped, then one is put back
/// after each component (the first scalar, or one after a ZWJ) that is
/// text by default and not followed by a skin-tone modifier or U+FE0E, and
/// between a keycap base and U+20E3. So "❤" and "❤\u{FE0F}" are the same
/// emoji, spelled "❤\u{FE0F}" as the emoji keyboard types it, and a set
/// holding both is a duplicate. Idempotent; `s` is not validated.
#[must_use]
pub fn canonical(s: &str) -> String {
    let chars: Vec<char> = s.chars().filter(|c| *c != '\u{FE0F}').collect();
    let mut out = String::with_capacity(s.len() + 3);
    for (i, &c) in chars.iter().enumerate() {
        out.push(c);
        let next = chars.get(i + 1).copied();
        let starts = i == 0 || chars[i - 1] == '\u{200D}';
        let text_default = starts
            && in_table(TEXT_DEFAULT, c)
            && !next.is_some_and(|n| is_modifier(n) || n == '\u{FE0E}');
        let keycap = i == 0 && matches!(c, '0'..='9' | '#' | '*') && next == Some('\u{20E3}');
        if text_default || keycap {
            out.push('\u{FE0F}');
        }
    }
    out
}

/// `emojis` in their canonical spelling (`canonical`), checked as a set
/// (`check_set`): two spellings of one emoji are a duplicate.
///
/// # Errors
/// As `check_set`.
pub fn canonical_set(emojis: &[String]) -> Result<Vec<String>> {
    let out: Vec<String> = emojis.iter().map(|e| canonical(e)).collect();
    check_set(&out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoreError;
    use unicode_segmentation::UnicodeSegmentation;

    #[test]
    fn emoji_accepts_real_emoji() {
        for e in [
            "👍",
            "👍🏽",
            "👨\u{200D}👩\u{200D}👧\u{200D}👦",
            "🇫🇷",
            "1\u{FE0F}\u{20E3}",
            "❤\u{FE0F}",
            "\u{1F3F4}\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}",
            "\u{A9}\u{FE0F}",
        ] {
            assert_eq!(check_emoji(e), Ok(()), "{e:?}");
        }
    }

    #[test]
    fn emoji_refuses_non_emoji() {
        let long = format!("👍{}", "\u{FE0F}".repeat(10));
        assert_eq!(long.len(), 34);
        assert_eq!(long.graphemes(true).count(), 1);
        for e in [
            "a",
            "1",
            "",
            "👍👍",
            "\u{200D}",
            "\u{FE0F}",
            "é",
            long.as_str(),
        ] {
            assert_eq!(check_emoji(e), Err(CoreError::InvalidEmoji), "{e:?}");
        }
    }

    #[test]
    fn emoji_set_limits() {
        let pool = [
            "👍",
            "👎",
            "❤\u{FE0F}",
            "😂",
            "😮",
            "😢",
            "🙏",
            "🔥",
            "🎉",
            "🤔",
            "👀",
            "💯",
            "🙌",
            "😍",
            "🤝",
            "🚀",
            "✅",
            "⭐",
            "🍕",
            "🐶",
            "🌈",
        ];
        let s = |n: usize| {
            pool[..n]
                .iter()
                .map(|e| (*e).to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(check_set(&[]), Ok(()));
        assert_eq!(check_set(&s(20)), Ok(()));
        assert_eq!(check_set(&s(21)), Err(CoreError::TooManyEmoji));
        assert_eq!(
            check_set(&["👍".to_owned(), "👍".to_owned()]),
            Err(CoreError::InvalidEmoji)
        );
        assert_eq!(check_set(&["a".to_owned()]), Err(CoreError::InvalidEmoji));
    }

    #[test]
    fn canonical_spelling_is_fully_qualified() {
        let fq = [
            "👍",
            "👍🏽",
            "❤\u{FE0F}",
            "☝🏽",
            "1\u{FE0F}\u{20E3}",
            "#\u{FE0F}\u{20E3}",
            "🇫🇷",
            "\u{A9}\u{FE0F}",
            "👨\u{200D}👩\u{200D}👧\u{200D}👦",
            "🏳\u{FE0F}\u{200D}🌈",
            "🏳\u{FE0F}\u{200D}⚧\u{FE0F}",
            "❤\u{FE0F}\u{200D}🔥",
            "🏃\u{200D}♂\u{FE0F}",
            "🏋🏽\u{200D}♀\u{FE0F}",
            "🕵\u{FE0F}\u{200D}♂\u{FE0F}",
            "\u{1F3F4}\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}",
        ];
        for e in fq {
            // Fixed point, and idempotent.
            assert_eq!(canonical(e), e, "{e:?}");
            assert_eq!(canonical(&canonical(e)), e, "{e:?}");
            // Every U+FE0F removed, or one too many: the same spelling back.
            let bare: String = e.chars().filter(|c| *c != '\u{FE0F}').collect();
            assert_eq!(canonical(&bare), e, "{e:?}");
            assert_eq!(canonical(&format!("{e}\u{FE0F}")), e, "{e:?}");
        }
        // Text presentation asked for: kept as it is.
        assert_eq!(canonical("❤\u{FE0E}"), "❤\u{FE0E}");
    }

    #[test]
    fn canonical_set_dedups_spellings() {
        let set = |l: &[&str]| l.iter().map(|e| (*e).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            canonical_set(&set(&["❤", "👍\u{FE0F}"])),
            Ok(set(&["❤\u{FE0F}", "👍"]))
        );
        assert_eq!(
            canonical_set(&set(&["❤", "❤\u{FE0F}"])),
            Err(CoreError::InvalidEmoji)
        );
        assert_eq!(canonical_set(&set(&["a"])), Err(CoreError::InvalidEmoji));
    }

    #[test]
    fn pictographic_table_matches_segmentation() {
        // The table is a copy: regenerate it when the crate moves to a newer
        // Unicode version.
        assert_eq!(unicode_segmentation::UNICODE_VERSION, (17, 0, 0));
        assert!(!EXTENDED_PICTOGRAPHIC.is_empty());
        for &(lo, hi) in EXTENDED_PICTOGRAPHIC {
            assert!(lo <= hi);
            for c in [lo, hi] {
                // GB11: ExtPict Extend* ZWJ x ExtPict, so the join holds only
                // when the segmentation table agrees that `c` is pictographic.
                let s = format!("{c}\u{200D}{c}");
                assert_eq!(s.graphemes(true).count(), 1, "U+{:04X}", c as u32);
            }
        }
        for c in ['a', '1', 'é'] {
            let s = format!("{c}\u{200D}{c}");
            assert_eq!(s.graphemes(true).count(), 2, "{c}");
        }
    }
}
